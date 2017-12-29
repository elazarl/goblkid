package ext

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/elazarl/goblkid"
	"github.com/stretchr/testify/assert"
)

func testWithMkfs(t *testing.T, path string, cmd ...string) *goblkid.ProbeInfo {
	t.Helper()
	tmpfile, err := ioutil.TempFile(os.TempDir(), "goblkid_ext_test")
	tmpname := tmpfile.Name()
	assert.Nil(t, err)
	defer os.Remove(tmpname)
	Run(t, "truncate", "-s", "100K", tmpname)
	Run(t, path, append(cmd, tmpname)...)
	fd, err := os.Open(tmpname)
	assert.Nil(t, err)
	defer fd.Close()

	info := goblkid.ProbeInfo{DeviceReader: fd}
	sb := ext2GetSuper(&info)
	assert.Equal(t, ExtMagic[0].Magic, string(sb.Magic[:]))
	assert.True(t, Chain.Probe(&info))
	return &info

}

func TestExt2WithMkfs(t *testing.T) {
	label := "mylabel"
	info := testWithMkfs(t, "mkfs.ext2", "-L", label)
	assert.Equal(t, "ext2", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func TestExt3WithMkfs(t *testing.T) {
	t.Skip("from some reason, truncate -s 100K x;mkfs.ext3 x;blkid x;" +
		"identifies as ext2")
	label := "mylabel"
	info := testWithMkfs(t, "mkfs.ext3", "-L", label)
	assert.Equal(t, "ext3", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func TestExt4WithMkfs(t *testing.T) {
	label := "mylabel"
	info := testWithMkfs(t, "mkfs.ext4", "-L", label)
	assert.Equal(t, "ext4", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func Run(t *testing.T, name string, cmd ...string) {
	t.Helper()
	out, err := exec.Command(name, cmd...).CombinedOutput()
	if err != nil {
		t.Fatal(err, "cannot run", name, cmd, "got", string(out))
	}
}
