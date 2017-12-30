package ext

import (
	"testing"

	"github.com/elazarl/goblkid"
	"github.com/elazarl/goblkid/test"
	"github.com/stretchr/testify/assert"
)

func TestExt2WithMkfs(t *testing.T) {
	label := "mylabel"
	info, closer := test.RunAndParse(t, "mkfs.ext2", "-L", label)
	defer closer.Close()
	ensureExt(t, info)
	assert.Equal(t, "ext2", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func TestExt3WithMkfs(t *testing.T) {
	t.Skip("from some reason, truncate -s 100K x;mkfs.ext3 x;blkid x;" +
		"identifies as ext2")
	label := "mylabel"
	info, closer := test.RunAndParse(t, "mkfs.ext3", "-L", label)
	defer closer.Close()
	ensureExt(t, info)
	assert.Equal(t, "ext3", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func TestExt4WithMkfs(t *testing.T) {
	label := "mylabel"
	info, closer := test.RunAndParse(t, "mkfs.ext4", "-L", label)
	defer closer.Close()
	ensureExt(t, info)
	assert.Equal(t, "ext4", info.ProbeName)
	assert.Equal(t, label, info.Label)
}

func ensureExt(t *testing.T, info *goblkid.ProbeInfo) {
	t.Helper()

	sb := ext2GetSuper(info)
	assert.Equal(t, ExtMagic[0].Magic, string(sb.Magic[:]))
	assert.True(t, Chain.Probe(info))
}
