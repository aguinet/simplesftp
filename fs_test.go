package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/pkg/sftp"
)

// setupRoot creates a temporary directory tree:
//
//	root/
//	  file.txt        ("hello")
//	  subdir/
//	    nested.txt    ("nested")
//	  link -> file.txt  (symlink)
//
// and a sibling file outside root:
//
//	parent/
//	  secret.txt      ("secret")
//	  root/           (the root above)
func setupRoot(t *testing.T) (root string) {
	t.Helper()
	parent := t.TempDir()
	root = filepath.Join(parent, "root")

	must(t, os.MkdirAll(filepath.Join(root, "subdir"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "subdir", "nested.txt"), []byte("nested"), 0o644))
	must(t, os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644))
	must(t, os.Symlink(filepath.Join(root, "file.txt"), filepath.Join(root, "link")))
	return root
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newFS(root string) *roFS { return &roFS{root: root} }

// fakeRequest builds an sftp.Request with the filepath set directly,
// bypassing sftp.NewRequest which calls path.Clean and would silently
// absorb traversal sequences before our abs() check ever runs.
func fakeRequest(method, path string) *sftp.Request {
	r := sftp.NewRequest(method, "/") // dummy clean path to satisfy the constructor
	r.Filepath = path                 // overwrite with the raw path we actually want to test
	return r
}

// readAll drains a ReaderAt into a []byte.
func readAll(t *testing.T, ra io.ReaderAt) []byte {
	t.Helper()
	var buf []byte
	tmp := make([]byte, 512)
	var off int64
	for {
		n, err := ra.ReadAt(tmp, off)
		buf = append(buf, tmp[:n]...)
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadAt: %v", err)
		}
	}
	return buf
}

// --- abs() path resolution ---

func TestAbs_RootItself(t *testing.T) {
	root := t.TempDir()
	fs := newFS(root)
	got, err := fs.abs("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != root {
		t.Fatalf("want %q got %q", root, got)
	}
}

func TestAbs_NormalFile(t *testing.T) {
	root := t.TempDir()
	fs := newFS(root)
	got, err := fs.abs("/foo/bar.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(root, "foo", "bar.txt")
	if got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestAbs_DotSegmentsInsideRoot(t *testing.T) {
	root := t.TempDir()
	fs := newFS(root)
	// /subdir/../file.txt stays inside root — must not be rejected.
	got, err := fs.abs("/subdir/../file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(root, "file.txt")
	if got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

// --- Fileread ---

func TestFileread_NormalFile(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	ra, err := fs.Fileread(fakeRequest("Get", "/file.txt"))
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	if c, ok := ra.(io.Closer); ok {
		defer c.Close()
	}
	data := readAll(t, ra)
	if string(data) != "hello" {
		t.Fatalf("want %q got %q", "hello", data)
	}
}

func TestFileread_NestedFile(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	ra, err := fs.Fileread(fakeRequest("Get", "/subdir/nested.txt"))
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	if c, ok := ra.(io.Closer); ok {
		defer c.Close()
	}
	data := readAll(t, ra)
	if string(data) != "nested" {
		t.Fatalf("want %q got %q", "nested", data)
	}
}

func TestFileread_NotFound(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	_, err := fs.Fileread(fakeRequest("Get", "/nonexistent.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- Filewrite / Filecmd (always denied) ---

func TestFilewrite_AlwaysDenied(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	_, err := fs.Filewrite(fakeRequest("Put", "/file.txt"))
	if err != sftp.ErrSSHFxPermissionDenied {
		t.Fatalf("want ErrSSHFxPermissionDenied, got %v", err)
	}
}

func TestFilecmd_AlwaysDenied(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	for _, method := range []string{"Rename", "Remove", "Mkdir", "Rmdir", "Setstat", "Symlink"} {
		err := fs.Filecmd(fakeRequest(method, "/file.txt"))
		if err != sftp.ErrSSHFxPermissionDenied {
			t.Fatalf("method %s: want ErrSSHFxPermissionDenied, got %v", method, err)
		}
	}
}

// --- Filelist / List ---

func TestFilelist_List_Root(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	la, err := fs.Filelist(fakeRequest("List", "/"))
	if err != nil {
		t.Fatalf("Filelist List: %v", err)
	}
	infos := drainLister(t, la)
	names := fileNames(infos)
	assert.Contains(t, names, "file.txt")
	assert.Contains(t, names, "subdir")
	assert.Contains(t, names, "link")
}

func TestFilelist_List_Subdir(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	la, err := fs.Filelist(fakeRequest("List", "/subdir"))
	if err != nil {
		t.Fatalf("Filelist List subdir: %v", err)
	}
	infos := drainLister(t, la)
	names := fileNames(infos)
	assert.Contains(t, names, "nested.txt")
}

func TestFilelist_List_TraversalEscape(t *testing.T) {
	root := "/this/is/the/root"
	fs := newFS(root)

	abs, err := fs.abs("/../")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root)

	abs, err = fs.abs("/subdir/../../")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root)

	abs, err = fs.abs("/../secret")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root + "/secret")

	abs, err = fs.abs("/a/b/c/../../../../../../../etc/passwd")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root + "/etc/passwd")

	abs, err = fs.abs("../../etc/passwd")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root + "/etc/passwd")

	abs, err = fs.abs("/subdir/../../secret")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root + "/secret")

	abs, err = fs.abs("/../file.txt")
	if err != nil {
		t.Fatal("expected not error, got ", err)
	}
	assert.Equal(t, abs, root + "/file.txt")
}

// --- Filelist / Stat ---

func TestFilelist_Stat_File(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	la, err := fs.Filelist(fakeRequest("Stat", "/file.txt"))
	if err != nil {
		t.Fatalf("Filelist Stat: %v", err)
	}
	infos := drainLister(t, la)
	if len(infos) != 1 {
		t.Fatalf("want 1 entry, got %d", len(infos))
	}
	if infos[0].Name() != "file.txt" {
		t.Fatalf("want file.txt got %s", infos[0].Name())
	}
}

func TestFilelist_Stat_TraversalEscape(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	_, err := fs.Filelist(fakeRequest("Stat", "/../secret.txt"))
	if err == nil {
		t.Fatal("expected path escape error")
	}
}

// --- Filelist / Lstat ---

func TestFilelist_Lstat_Symlink(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	la, err := fs.Filelist(fakeRequest("Lstat", "/link"))
	if err != nil {
		t.Fatalf("Filelist Lstat: %v", err)
	}
	infos := drainLister(t, la)
	if len(infos) != 1 {
		t.Fatalf("want 1 entry, got %d", len(infos))
	}
	if !isSymlink(infos[0]) {
		t.Fatal("expected symlink mode")
	}
}

func TestFilelist_Lstat_TraversalEscape(t *testing.T) {
	root := setupRoot(t)
	fs := newFS(root)
	_, err := fs.Filelist(fakeRequest("Lstat", "/subdir/../../../secret.txt"))
	if err == nil {
		t.Fatal("expected path escape error")
	}
}

// --- listerat ---

func TestListerat_Empty(t *testing.T) {
	l := listerat(nil)
	ls := make([]os.FileInfo, 2)
	n, err := l.ListAt(ls, 0)
	if n != 0 || err != io.EOF {
		t.Fatalf("want (0, EOF) got (%d, %v)", n, err)
	}
}

func TestListerat_OffsetBeyondEnd(t *testing.T) {
	root := setupRoot(t)
	info, _ := os.Stat(filepath.Join(root, "file.txt"))
	l := listerat([]os.FileInfo{info})
	ls := make([]os.FileInfo, 2)
	n, err := l.ListAt(ls, 5)
	if n != 0 || err != io.EOF {
		t.Fatalf("want (0, EOF) got (%d, %v)", n, err)
	}
}

func TestListerat_PartialRead(t *testing.T) {
	root := setupRoot(t)
	fi1, _ := os.Stat(filepath.Join(root, "file.txt"))
	fi2, _ := os.Stat(filepath.Join(root, "subdir"))
	l := listerat([]os.FileInfo{fi1, fi2})
	ls := make([]os.FileInfo, 1)

	// First read: one item available, buffer not exhausted yet — no EOF.
	n, err := l.ListAt(ls, 0)
	if n != 1 || err != nil {
		t.Fatalf("first read: want (1, nil) got (%d, %v)", n, err)
	}

	// Second read: one item available, exactly fills buffer — no EOF yet;
	// caller must issue one more read to learn the list is done.
	n, err = l.ListAt(ls, 1)
	if n != 1 || err != nil {
		t.Fatalf("second read: want (1, nil) got (%d, %v)", n, err)
	}

	// Third read: offset past end — signals EOF.
	n, err = l.ListAt(ls, 2)
	if n != 0 || err != io.EOF {
		t.Fatalf("third read: want (0, EOF) got (%d, %v)", n, err)
	}
}

// --- helpers ---

func drainLister(t *testing.T, la sftp.ListerAt) []os.FileInfo {
	t.Helper()
	var all []os.FileInfo
	buf := make([]os.FileInfo, 16)
	var off int64
	for {
		n, err := la.ListAt(buf, off)
		all = append(all, buf[:n]...)
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ListAt: %v", err)
		}
	}
	return all
}

func fileNames(infos []os.FileInfo) []string {
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	return names
}

func isSymlink(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSymlink != 0
}
