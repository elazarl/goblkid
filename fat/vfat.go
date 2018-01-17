package fat

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/elazarl/goblkid"
)

var Chain = goblkid.Chain{
	FATProber,
}

func vfatProbe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) bool {
	_, err := info.DeviceReader.Seek(int64(magic.SuperblockKbOffset<<10), io.SeekStart)
	if err != nil {
		return false
	}
	ms, vs, err := vfatGetSuperblock(info.DeviceReader)
	if err != nil {
		return false
	}

	if !isFATValidSuperblock(ms, vs, magic) {
		return false
	}
	fat_size := fatSize(ms, vs)
	cluster_count := fatClusterCount(ms, vs)

	version := ""
	if ms.FatLength != 0 {
		root_start := (uint32(ms.Reserved) + fat_size) * uint32(ms.SectorSize)
		info.Label = searchFATLabel(info, uint64(root_start), uint32(vs.DirEntries))
		info.SecType = "msdos"
		if cluster_count < FAT12_MAX {
			version = "FAT12"
		} else if cluster_count < FAT16_MAX {
			version = "FAT16"
		}
		info.UUID = fmt.Sprintf("%02X%02X-%02X%02X",
			ms.Serno[3], ms.Serno[2], ms.Serno[1], ms.Serno[0])
	} else if vs.Fat32Length != 0 {
		bufSize := uint32(vs.ClusterSize) + uint32(ms.SectorSize)
		start_data_sect := uint32(ms.Reserved) + fat_size
		entries := vs.Fat32Length * uint32(ms.SectorSize) / 4 // 4=sizeof(uint32)
		next := uint32(vs.RootCluster)

		vfat_dir_entry_size := uint32(32)
		for maxloop := 100; next != 0 && next < entries && maxloop > 0; maxloop-- {
			next_sect_off := (next - 2) * uint32(vs.ClusterSize)
			next_off := uint64(start_data_sect+next_sect_off) * uint64(ms.SectorSize)
			count := bufSize / vfat_dir_entry_size
			info.Label = searchFATLabel(info, next_off, count)

			fat_entry_off := uint64(ms.Reserved)*uint64(ms.SectorSize) +
				uint64(next)*4 // 4=sizeof(uint32)
			info.DeviceReader.Seek(int64(fat_entry_off), io.SeekStart)
			binary.Read(info.DeviceReader, binary.LittleEndian, &next)
			next &= 0x0fffffff
		}
		version = "FAT32"
		info.UUID = fmt.Sprintf("%02X%02X-%02X%02X",
			vs.Serno[3], vs.Serno[2], vs.Serno[1], vs.Serno[0])
	}

	info.Version = version

	return true
}

func searchFATLabel(info *goblkid.ProbeInfo, root_start uint64, dir_entries uint32) string {
	info.DeviceReader.Seek(int64(root_start), io.SeekStart)
	for i := uint32(0); i < dir_entries; i++ {
		ent, err := unpack_vfat_dir_entry(info.DeviceReader)
		if err != nil {
			panic(err)
		}
		if ent.Name[0] == 0 {
			break
		}
		if ent.Name[0] == FAT_ENTRY_FREE ||
			ent.ClusterHigh != 0 ||
			ent.ClusterLow != 0 ||
			ent.Attr&FAT_ATTR_MASK == FAT_ATTR_LONG_NAME {
			continue
		}
		if ent.Attr&(FAT_ATTR_VOLUME_ID|FAT_ATTR_DIR) == FAT_ATTR_VOLUME_ID {
			return strings.TrimRight(string(ent.Name[:]), " \n\t")
		}
	}
	return ""
}

func fatSize(ms *msdos_super_block, vs *vfat_super_block) uint32 {
	var fat_length = uint32(ms.FatLength)
	if fat_length == 0 {
		fat_length = vs.Fat32Length
	}
	return fat_length * uint32(ms.Fats)
}

func fatClusterCount(ms *msdos_super_block, vs *vfat_super_block) uint32 {
	entry_size := uint32(32)
	fat_size := fatSize(ms, vs)

	dir_size := (uint32(ms.DirEntries)*entry_size + uint32(ms.SectorSize-1)) / uint32(ms.SectorSize)
	return (uint32(ms.Sectors) - (uint32(ms.Reserved) + fat_size + dir_size)) / uint32(ms.ClusterSize)
}

func isFATValidSuperblock(ms *msdos_super_block, vs *vfat_super_block, magic goblkid.MagicInfo) bool {
	if len(magic.Magic) <= 2 {
		/* Old floppies have a valid MBR signature */
		if ms.Pmagic[0] != 0x55 || ms.Pmagic[1] != 0xAA {
			return false
		}

		/*
		 * OS/2 and apparently DFSee will place a FAT12/16-like
		 * pseudo-superblock in the first 512 bytes of non-FAT
		 * filesystems --- at least JFS and HPFS, and possibly others.
		 * So we explicitly check for those filesystems at the
		 * FAT12/16 filesystem magic field identifier, and if they are
		 * present, we rule this out as a FAT filesystem, despite the
		 * FAT-like pseudo-header.
		 */
		if string(ms.Magic[:]) == "JFS     " || string(ms.Magic[:]) == "HPFS    " {
			return false
		}
	}

	/* fat counts(Linux kernel expects at least 1 FAT table) */
	if ms.Fats == 0 {
		return false
	}
	if ms.Reserved == 0 {
		return false
	}
	if !(0xf8 <= ms.Media || ms.Media == 0xf0) {
		return false
	}
	if !isPowerOf2(int(ms.ClusterSize)) {
		return false
	}

	if !isPowerOf2(int(ms.SectorSize)) ||
		ms.SectorSize < 512 ||
		ms.SectorSize > 4096 {
		return false
	}

	sectors := uint32(ms.Sectors)
	if sectors == 0 {
		sectors = ms.TotalSect
	}
	fat_length := uint32(ms.FatLength)
	if fat_length == 0 {
		fat_length = vs.Fat32Length
	}

	entry_size := uint32(32)
	fat_size := fat_length * uint32(ms.Fats)
	dir_size := (uint32(ms.DirEntries)*entry_size + uint32(ms.SectorSize-1)) / uint32(ms.SectorSize)
	cluster_count := (sectors - (uint32(ms.Reserved) + fat_size + dir_size)) / uint32(ms.ClusterSize)

	max_count := uint32(FAT12_MAX)
	if cluster_count > FAT12_MAX {
		max_count = FAT16_MAX
	}
	if ms.FatLength == 0 && vs.Fat32Length != 0 {
		max_count = FAT32_MAX
	}

	if cluster_count > max_count {
		return false
	}
	/* TODO: missing whole-disk heuristic, to exclude MBRs that looks like FAT */

	return true
}

var FATProber = goblkid.Prober{
	Name:      "vfat",
	Usage:     goblkid.FilesystemProbe,
	ProbeFunc: vfatProbe,
	MagicInfos: []goblkid.MagicInfo{
		{"MSWIN", 0, 0x52},
		{"FAT32", 0, 0x52},
		{"MSDOS", 0, 0x36},
		{"FAT16", 0, 0x36},
		{"FAT12", 0, 0x36},
		{"FAT", 0, 0x36},
		{"\353", 0, 0},
		{"\351", 0, 0},
		{"\125\252", 0, 0x1fe},
	},
}

const SuperblockSize = 512

func vfatGetSuperblock(r io.Reader) (*msdos_super_block, *vfat_super_block, error) {
	buf := make([]byte, 512)
	if _, err := io.ReadAtLeast(r, buf, SuperblockSize); err != nil {
		return nil, nil, err
	}
	common := superblock_common{}
	copy(common.Ignored[:], buf[:3])
	copy(common.Sysid[:], buf[3:0xb])
	common.SectorSize = binary.LittleEndian.Uint16(buf[0x0b:0x0d])
	common.ClusterSize = buf[0x0d]
	common.Reserved = binary.LittleEndian.Uint16(buf[0x0e:0x10])
	common.Fats = buf[0x10]
	common.DirEntries = binary.LittleEndian.Uint16(buf[0x11:0x13])
	common.Sectors = binary.LittleEndian.Uint16(buf[0x13:0x15])
	common.Media = buf[0x15]
	common.FatLength = binary.LittleEndian.Uint16(buf[0x16:0x18])
	common.SecsTrack = binary.LittleEndian.Uint16(buf[0x18:0x1a])
	common.Heads = binary.LittleEndian.Uint16(buf[0x1a:0x1c])
	common.Hidden = binary.LittleEndian.Uint32(buf[0x1c:0x20])
	common.TotalSect = binary.LittleEndian.Uint32(buf[0x20:0x24])

	ms := &msdos_super_block{superblock_common: common}
	copy(ms.Unknown[:], buf[0x24:0x24+3])
	copy(ms.Serno[:], buf[0x27:0x2b])
	copy(ms.Label[:], buf[0x2b:0x36])
	copy(ms.Magic[:], buf[0x36:0x3e])
	copy(ms.Dummy2[:], buf[0x3e:0x1fe])
	copy(ms.Pmagic[:], buf[0x1fe:0x200])

	vs := &vfat_super_block{superblock_common: common}
	vs.Fat32Length = binary.LittleEndian.Uint32(buf[0x24:0x28])
	vs.Flags = binary.LittleEndian.Uint16(buf[0x28:0x2a])
	vs.Version = binary.LittleEndian.Uint16(buf[0x2a:0x2c])
	vs.RootCluster = binary.LittleEndian.Uint32(buf[0x2c:0x30])
	vs.FsinfoSector = binary.LittleEndian.Uint16(buf[0x30:0x32])
	vs.BackupBoot = binary.LittleEndian.Uint16(buf[0x32:0x34])
	copy(vs.Reserved2[:], buf[0x34:0x40])
	copy(vs.Unknown[:], buf[0x40:0x43])
	copy(vs.Serno[:], buf[0x43:0x47])
	copy(vs.Label[:], buf[0x47:0x52])
	copy(vs.Magic[:], buf[0x52:0x5a])
	copy(vs.Dummy2[:], buf[0x5a:0x1fe])
	copy(vs.Pmagic[:], buf[0x1fe:0x200])

	return ms, vs, nil
}

type superblock_common struct {
	/* 00*/ Ignored [3]uint8
	/* 03*/ Sysid [8]uint8
	/* 0b*/ SectorSize uint16
	/* 0d*/ ClusterSize uint8
	/* 0e*/ Reserved uint16
	/* 10*/ Fats uint8
	/* 11*/ DirEntries uint16
	/* 13*/ Sectors uint16 /* =0 iff V3 or later */
	/* 15*/ Media uint8
	/* 16*/ FatLength uint16 /* Sectors per FAT */
	/* 18*/ SecsTrack uint16
	/* 1a*/ Heads uint16
	/* 1c*/ Hidden uint32 /* V3 BPB */
	/* 20*/
	TotalSect uint32 /* iff ms.Sectors == 0 */
}

/* Yucky misaligned values */
type vfat_super_block struct {
	superblock_common
	/* 24*/ Fat32Length uint32
	/* 28*/ Flags uint16
	/* 2a*/ Version uint16
	/* 2c*/ RootCluster uint32
	/* 30*/ FsinfoSector uint16
	/* 32*/ BackupBoot uint16
	/* 34*/ Reserved2 [12]uint8
	/* 40*/ Unknown [3]uint8
	/* 43*/ Serno [4]uint8
	/* 47*/ Label [11]uint8
	/* 52*/ Magic [8]uint8
	/* 5a*/ Dummy2 [0x1fe - 0x5a]uint8
	/*1fe*/ Pmagic [2]uint8
}

/* Yucky misaligned values */
type msdos_super_block struct {
	superblock_common
	/* V4 BPB */
	/* 24*/
	Unknown [3]uint8 /* Phys drive no., resvd, V4 sig (0x29) */
	/* 27*/ Serno [4]uint8
	/* 2b*/ Label [11]uint8
	/* 36*/ Magic [8]uint8
	/* 3e*/ Dummy2 [0x1fe - 0x3e]uint8
	/*1fe*/ Pmagic [2]uint8
}

type vfat_dir_entry struct {
	Name        string `struc:"[11]uint8"` /* 0-10 */
	Attr        uint8  /* 11 */
	TimeCreat   uint16 /* 12-13 */
	DateCreat   uint16 /* 14-15 */
	TimeAcc     uint16 /* 16-17 */
	DateAcc     uint16 /* 18-19 */
	ClusterHigh uint16 /* 20-21 */
	TimeWrite   uint16 /* 22-23 */
	DateWrite   uint16 /* 24-25 */
	ClusterLow  uint16 /* 26-27 */
	Size        uint32 /* 28-31 */
}

func unpack_vfat_dir_entry(r io.Reader) (*vfat_dir_entry, error) {
	size := 11 + 1 + 8*2 + 4
	b := make([]byte, size)
	if _, err := io.ReadAtLeast(r, b, len(b)); err != nil {
		return nil, err
	}
	return &vfat_dir_entry{
		string(b[0:11]),
		b[11],
		binary.LittleEndian.Uint16(b[12:14]),
		binary.LittleEndian.Uint16(b[14:16]),
		binary.LittleEndian.Uint16(b[16:18]),
		binary.LittleEndian.Uint16(b[18:20]),
		binary.LittleEndian.Uint16(b[20:22]),
		binary.LittleEndian.Uint16(b[22:24]),
		binary.LittleEndian.Uint16(b[24:26]),
		binary.LittleEndian.Uint16(b[26:28]),
		binary.LittleEndian.Uint32(b[28:32]),
	}, nil
}

const FAT12_MAX = 0xFF4
const FAT16_MAX = 0xFFF4
const FAT32_MAX = 0x0FFFFFF6

const FAT_ATTR_VOLUME_ID = 0x08
const FAT_ATTR_DIR = 0x10
const FAT_ATTR_LONG_NAME = 0x0f
const FAT_ATTR_MASK = 0x3f
const FAT_ENTRY_FREE = 0xe5

var no_name = "NO NAME    "

func isPowerOf2(num int) bool {
	return (num != 0 && ((num & (num - 1)) == 0))
}
