package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "creds.yaml")
	must(t, os.WriteFile(f, []byte(content), 0o600))
	return f
}

func TestLoadCredFile_Passwords(t *testing.T) {
	f := writeYAML(t, `
pass:
  - user: alice
    password: secret
  - user: bob
    password: hunter2
`)
	creds, err := loadCredFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds, got %d", len(creds))
	}
	if creds[0].username != "alice" || creds[0].password != "secret" {
		t.Errorf("unexpected cred[0]: %+v", creds[0])
	}
	if creds[1].username != "bob" || creds[1].password != "hunter2" {
		t.Errorf("unexpected cred[1]: %+v", creds[1])
	}
}

// A real (but throwaway) ed25519 public key in authorized_keys format.
const testPubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test"

func TestLoadCredFile_Pubkeys(t *testing.T) {
	yaml := `pubkeys:
  - user: carol
    pubkey: |
      ` + testPubkey
	f := writeYAML(t, yaml)
	creds, err := loadCredFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 cred, got %d", len(creds))
	}
	if creds[0].username != "carol" {
		t.Errorf("want user carol, got %q", creds[0].username)
	}
	if creds[0].publicKey == nil {
		t.Error("expected publicKey to be set")
	}
}

func TestLoadCredFile_Mixed(t *testing.T) {
	yaml := `pass:
  - user: alice
    password: secret
pubkeys:
  - user: carol
    pubkey: |
      ` + testPubkey
	f := writeYAML(t, yaml)
	creds, err := loadCredFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds, got %d", len(creds))
	}
	passwords, pubkeys := 0, 0
	for _, c := range creds {
		if c.publicKey != nil {
			pubkeys++
		} else {
			passwords++
		}
	}
	if passwords != 1 || pubkeys != 1 {
		t.Errorf("want 1 password + 1 pubkey, got %d + %d", passwords, pubkeys)
	}
}

func TestLoadCredFile_Empty(t *testing.T) {
	f := writeYAML(t, "")
	creds, err := loadCredFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds, got %d", len(creds))
	}
}

func TestLoadCredFile_MissingUser(t *testing.T) {
	f := writeYAML(t, `pass:
  - password: secret
`)
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestLoadCredFile_MissingPassword(t *testing.T) {
	f := writeYAML(t, `pass:
  - user: alice
`)
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestLoadCredFile_MissingPubkeyUser(t *testing.T) {
	yaml := `pubkeys:
  - pubkey: |
      ` + testPubkey
	f := writeYAML(t, yaml)
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestLoadCredFile_MissingPubkeyValue(t *testing.T) {
	f := writeYAML(t, `pubkeys:
  - user: carol
`)
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for missing pubkey value")
	}
}

func TestLoadCredFile_InvalidPubkey(t *testing.T) {
	f := writeYAML(t, `pubkeys:
  - user: carol
    pubkey: not-a-valid-key
`)
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestLoadCredFile_InvalidYAML(t *testing.T) {
	f := writeYAML(t, ":	:invalid yaml{{")
	_, err := loadCredFile(f)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadCredFile_NotFound(t *testing.T) {
	_, err := loadCredFile("/nonexistent/path/creds.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
