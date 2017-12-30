package test

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/elazarl/goblkid"
	"github.com/stretchr/testify/assert"
)

func RunAndParse(t *testing.T, path string, cmd ...string) (*goblkid.ProbeInfo, io.Closer) {
	t.Helper()
	tmpfile, err := ioutil.TempFile(os.TempDir(), "goblkid_ext_test")
	tmpname := tmpfile.Name()
	assert.Nil(t, err)
	defer os.Remove(tmpname)
	Run(t, "truncate", "-s", "100K", tmpname)
	Run(t, path, append(cmd, tmpname)...)
	fd, err := os.Open(tmpname)
	assert.Nil(t, err)

	info := goblkid.ProbeInfo{DeviceReader: fd}
	return &info, closer(func() { fd.Close() })

}

func Run(t *testing.T, name string, cmd ...string) {
	t.Helper()
	out, err := exec.Command(name, cmd...).CombinedOutput()
	if err != nil {
		t.Fatal(err, "cannot run", name, cmd, "got", string(out))
	}
}

type closer func()

func (c closer) Close() error {
	c()
	return nil
}
