package goblkid

import "io"

type ProbeUsage int

const (
	FilesystemProbe ProbeUsage = 1 << iota
	RaidProbe
	CryptoProbe
	OtherProbe
)

func (pr *Prober) Probe(info *ProbeInfo) bool {
	for _, magic := range pr.MagicInfos {
		if pr.ProbeFunc(info, magic) {
			return true
		}
	}
	return false
}

type Prober struct {
	Name       string
	Usage      ProbeUsage
	ProbeFunc  func(info *ProbeInfo, magicInfo MagicInfo) bool
	MagicInfos []MagicInfo
}

type MagicInfo struct {
	Magic              string
	SuperblockKbOffset uint64
	MagicByteOffset    uint64
}

type ProbeInfo struct {
	DeviceReader io.ReadSeeker
	Offset       int64
	Size         int64

	Devno     int
	DiskDevno int
	BlockSize uint64 /* from BLKSSZGET ioctl */
	Mode      int    /* from stat.sb_mode */

	ProbeName string

	UUID  string
	Label string

	ExtJournal string
	SecType    string

	Version string
}
