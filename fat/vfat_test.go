package fat

import (
	"testing"

	"github.com/elazarl/goblkid/test"
	"github.com/stretchr/testify/assert"
)

func TestVfatWithMkfs(t *testing.T) {
	label := "mylabel"
	info, closer := test.RunAndParse(t, "mkfs.fat", "-n", label)
	defer closer.Close()
	Chain.Probe(info)
	assert.Equal(t, "vfat", info.ProbeName)
	assert.Equal(t, label, info.Label)
}
