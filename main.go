package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type credential struct {
	username  string
	password  string
	publicKey ssh.PublicKey
}

type credFlag struct {
	creds *[]credential
	isPub bool
}

func (f *credFlag) String() string { return "" }

func (f *credFlag) Set(s string) error {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("expected user:value")
	}
	user, value := parts[0], parts[1]

	if f.isPub {
		data, err := os.ReadFile(value)
		if err != nil {
			return fmt.Errorf("reading public key file %q: %w", value, err)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return fmt.Errorf("parsing public key file %q: %w", value, err)
		}
		*f.creds = append(*f.creds, credential{username: user, publicKey: pk})
	} else {
		*f.creds = append(*f.creds, credential{username: user, password: value})
	}
	return nil
}

// credFile is the structure of the YAML credentials file.
type credFile struct {
	Pass []struct {
		User     string `yaml:"user"`
		Password string `yaml:"password"`
	} `yaml:"pass"`
	Pubkeys []struct {
		User   string `yaml:"user"`
		Pubkey string `yaml:"pubkey"`
	} `yaml:"pubkeys"`
}

func loadCredFile(path string) ([]credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading credentials file: %w", err)
	}

	var cf credFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parsing credentials file: %w", err)
	}

	var creds []credential

	for i, entry := range cf.Pass {
		if entry.User == "" {
			return nil, fmt.Errorf("pass[%d]: missing user", i)
		}
		if entry.Password == "" {
			return nil, fmt.Errorf("pass[%d]: missing password (user %q)", i, entry.User)
		}
		creds = append(creds, credential{username: entry.User, password: entry.Password})
	}

	for i, entry := range cf.Pubkeys {
		if entry.User == "" {
			return nil, fmt.Errorf("pubkeys[%d]: missing user", i)
		}
		if entry.Pubkey == "" {
			return nil, fmt.Errorf("pubkeys[%d]: missing pubkey (user %q)", i, entry.User)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.Pubkey))
		if err != nil {
			return nil, fmt.Errorf("pubkeys[%d]: parsing public key for user %q: %w", i, entry.User, err)
		}
		creds = append(creds, credential{username: entry.User, publicKey: pk})
	}

	return creds, nil
}

// authEvent is the structured log line emitted for every login attempt.
type authEvent struct {
	Time   string `json:"time"`
	Event  string `json:"event"`  // "auth_ok" | "auth_fail"
	Method string `json:"method"` // "password" | "publickey"
	User   string `json:"user"`
	SrcIP  string `json:"src_ip"`
	Reason string `json:"reason,omitempty"`
}

func logAuth(e authEvent) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(e)
	log.Println(string(b))
}

func sourceIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func buildSSHConfig(creds []credential, hostKey ssh.Signer) *ssh.ServerConfig {
	passwordMap := map[string]string{}
	pubkeyMap := map[string][]ssh.PublicKey{}

	for _, c := range creds {
		if c.publicKey != nil {
			pubkeyMap[c.username] = append(pubkeyMap[c.username], c.publicKey)
		} else {
			passwordMap[c.username] = c.password
		}
	}

	config := &ssh.ServerConfig{}

	if len(passwordMap) > 0 {
		config.PasswordCallback = func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ev := authEvent{
				Method: "password",
				User:   conn.User(),
				SrcIP:  sourceIP(conn.RemoteAddr()),
			}
			if expected, ok := passwordMap[conn.User()]; ok && expected == string(pass) {
				ev.Event = "auth_ok"
				logAuth(ev)
				return nil, nil
			}
			ev.Event = "auth_fail"
			ev.Reason = "bad credentials"
			logAuth(ev)
			return nil, fmt.Errorf("password rejected for %q", conn.User())
		}
	}

	if len(pubkeyMap) > 0 {
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ev := authEvent{
				Method: "publickey",
				User:   conn.User(),
				SrcIP:  sourceIP(conn.RemoteAddr()),
			}
			keys, ok := pubkeyMap[conn.User()]
			if !ok {
				ev.Event = "auth_fail"
				ev.Reason = "unknown user"
				logAuth(ev)
				return nil, fmt.Errorf("public key rejected for %q", conn.User())
			}
			candidate := ssh.FingerprintSHA256(key)
			for _, k := range keys {
				if ssh.FingerprintSHA256(k) == candidate {
					ev.Event = "auth_ok"
					logAuth(ev)
					return nil, nil
				}
			}
			ev.Event = "auth_fail"
			ev.Reason = "bad credentials"
			logAuth(ev)
			return nil, fmt.Errorf("public key rejected for %q", conn.User())
		}
	}

	config.AddHostKey(hostKey)
	return config
}

func handleConn(conn net.Conn, config *ssh.ServerConfig, root string) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf(`{"time":%q,"event":"handshake_error","src_ip":%q,"reason":%q}`,
			time.Now().UTC().Format(time.RFC3339), sourceIP(conn.RemoteAddr()), err.Error())
		return
	}
	defer sshConn.Close()
	log.Printf(`{"time":%q,"event":"session_open","user":%q,"src_ip":%q}`,
		time.Now().UTC().Format(time.RFC3339), sshConn.User(), sourceIP(sshConn.RemoteAddr()))

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("accept channel: %v", err)
			return
		}

		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()
			for req := range requests {
				if req.Type == "subsystem" && len(req.Payload) >= 4 {
					if string(req.Payload[4:]) == "sftp" {
						if req.WantReply {
							req.Reply(true, nil)
						}
						srv := sftp.NewRequestServer(ch, readonlyHandlers(root))
						if err := srv.Serve(); err != nil && err != io.EOF {
							log.Printf("SFTP serve error: %v", err)
						}
						return
					}
				}
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

func readonlyHandlers(root string) sftp.Handlers {
	fs := &roFS{root: root}
	return sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs}
}

type roFS struct{ root string }

func (fs *roFS) abs(p string) (string, error) {
	full := filepath.Join(fs.root, filepath.Clean("/"+p))

	// Final guard that verifies that 'full' is really relative to fs.root!
	_, err := filepath.Rel(fs.root, full)
	if err != nil {
		return "", fmt.Errorf("path escape")
	}

	return full, nil
}

func (fs *roFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := fs.abs(r.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (fs *roFS) Filewrite(*sftp.Request) (io.WriterAt, error) {
	return nil, sftp.ErrSSHFxPermissionDenied
}

func (fs *roFS) Filecmd(*sftp.Request) error {
	return sftp.ErrSSHFxPermissionDenied
}

func (fs *roFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := fs.abs(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			infos = append(infos, info)
		}
		return listerat(infos), nil
	case "Stat", "Lstat":
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return listerat([]os.FileInfo{info}), nil
	case "Readlink":
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(filepath.Join(fs.root, filepath.Clean("/"+target)))
		if err != nil {
			return nil, err
		}
		return listerat([]os.FileInfo{info}), nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

type listerat []os.FileInfo

func (l listerat) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func main() {
	addr := flag.String("addr", ":2022", "listen address")
	dir := flag.String("dir", ".", "directory to serve")
	keyFile := flag.String("key", "", "path to openssh private host key (required)")
	credsFile := flag.String("creds-file", "", "path to YAML credentials file (optional, repeatable via multiple flags is not supported; combine with -pass/-pubkey)")

	var creds []credential
	flag.Var(&credFlag{creds: &creds, isPub: false}, "pass", "user:password (repeatable)")
	flag.Var(&credFlag{creds: &creds, isPub: true}, "pubkey", "user:/path/to/key.pub (repeatable)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -key <host_key> -dir <dir> [-pass user:pass] [-pubkey user:/path/to/key.pub] [-creds-file file.yaml]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nYAML credentials file format:\n")
		fmt.Fprintf(os.Stderr, "  pass:\n    - user: alice\n      password: secret\n  pubkeys:\n    - user: bob\n      pubkey: |\n        ssh-ed25519 AAAA...\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -key /etc/ssh/ssh_host_ed25519_key -dir /data -pass alice:secret\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -key /etc/ssh/ssh_host_ed25519_key -dir /data -creds-file /etc/sftp-users.yaml\n", os.Args[0])
	}
	flag.Parse()

	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "error: -key is required")
		flag.Usage()
		os.Exit(1)
	}

	if *credsFile != "" {
		fileCreds, err := loadCredFile(*credsFile)
		if err != nil {
			log.Fatalf("credentials file: %v", err)
		}
		creds = append(creds, fileCreds...)
	}

	if len(creds) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one -pass, -pubkey, or -creds-file entry is required")
		flag.Usage()
		os.Exit(1)
	}

	pemBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("read host key: %v", err)
	}
	hostKey, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("parse host key: %v", err)
	}

	root, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("invalid directory: %v", err)
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		log.Fatalf("directory does not exist: %s", root)
	}

	config := buildSSHConfig(creds, hostKey)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf(`{"time":%q,"event":"server_start","addr":%q,"dir":%q}`,
		time.Now().UTC().Format(time.RFC3339), listener.Addr().String(), root)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, config, root)
	}
}
