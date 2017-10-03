// /proc/net/rpc/nfsd parsing documented by https://www.svennd.be/nfsd-stats-explained-procnetrpcnfsd/
package procfs

import (
	"bufio"
	"fmt"
	"io"
)

// rc line: Reply Cache
type NFSdReplyCache struct {
	Hits    uint64
	Misses  uint64
	NoCache uint64
}

// fh line: File Handles
type NFSdFileHandles struct {
	Stale        uint64
	TotalLookups uint64
	AnonLookups  uint64
	DirNoCache   uint64
	NoDirNoCache uint64
}

// io line: Input Output
type NFSdInputOutput struct {
	Read  uint64
	Write uint64
}

// th line: Threads
type NFSdThreads struct {
	Threads uint64
	FullCnt uint64
}

// ra line: Read Ahead Cache
type NFSdReadAheadCache struct {
	CacheSize      uint64
	CacheHistogram [10]uint64
	NotFound       uint64
}

// net line: Network
type NFSdNetwork struct {
	NetCount   uint64
	UDPCount   uint64
	TCPCount   uint64
	TCPConnect uint64
}

// rpc line:
type NFSdRPC struct {
	RPCCount uint64
	BadCnt   uint64
	BadFmt   uint64
	BadAuth  uint64
	BadcInt  uint64
}

// proc2 line: NFSv2 Stats
type NFSdv2Stats struct {
	Values   uint64 // Should be 18.
	Null     uint64
	GetAttr  uint64
	SetAttr  uint64
	Root     uint64
	Lookup   uint64
	ReadLink uint64
	Read     uint64
	WrCache  uint64
	Write    uint64
	Create   uint64
	Remove   uint64
	Rename   uint64
	Link     uint64
	SymLink  uint64
	MkDir    uint64
	RmDir    uint64
	ReadDir  uint64
	FsStat   uint64
}

// proc3 line: NFSv3 Stats
type NFSdv3Stats struct {
	Values      uint64 // Should be 22.
	Null        uint64
	GetAttr     uint64
	SetAttr     uint64
	Lookup      uint64
	Access      uint64
	ReadLink    uint64
	Read        uint64
	Write       uint64
	Create      uint64
	MkDir       uint64
	SymLink     uint64
	MkNod       uint64
	Remove      uint64
	RmDir       uint64
	Rename      uint64
	Link        uint64
	ReadDir     uint64
	ReadDirPlus uint64
	FsStat      uint64
	FsInfo      uint64
	PathConf    uint64
	Commit      uint64
}

// proc4 line: NFSv4 Stats
type NFSdv4Stats struct {
	Values   uint64 // Should be 2.
	Null     uint64
	Compound uint64
}

// proc4ops line: NFSv4 operations
// Variable list, see:
// v4.0 https://tools.ietf.org/html/rfc3010 (38 operations)
// v4.1 https://tools.ietf.org/html/rfc5661 (58 operations)
// v4.2 https://tools.ietf.org/html/draft-ietf-nfsv4-minorversion2-41 (71 operations)
type NFSdv4Ops struct {
	Values       uint64 // Variable depending on v4.x sub-version.
	Op0Unused    uint64
	Op1Unused    uint64
	Op2Future    uint64
	Access       uint64
	Close        uint64
	Commit       uint64
	Create       uint64
	DelegPurge   uint64
	DelegReturn  uint64
	GetAttr      uint64
	GetFH        uint64
	Link         uint64
	Lock         uint64
	Lockt        uint64
	Locku        uint64
	Lookup       uint64
	LookupRoot   uint64
	Nverify      uint64
	Open         uint64
	OpenAttr     uint64
	OpenConfirm  uint64
	OpenDgrd     uint64
	PutFH        uint64
	PutPubFH     uint64
	PutRootFH    uint64
	Read         uint64
	ReadDir      uint64
	ReadLink     uint64
	Remove       uint64
	Rename       uint64
	Renew        uint64
	RestoreFH    uint64
	SaveFH       uint64
	SecInfo      uint64
	SetAttr      uint64
	Verify       uint64
	Write        uint64
	RelLockOwner uint64
}

// All stats from /proc/net/rpc/nfsd
type NFSdRPCStats struct {
	NFSdReplyCache     NFSdReplyCache
	NFSdFileHandles    NFSdFileHandles
	NFSdInputOutput    NFSdInputOutput
	NFSdThreads        NFSdThreads
	NFSdReadAheadCache NFSdReadAheadCache
	NFSdNetwork        NFSdNetwork
	NFSdRPC            NFSdRPC
	NFSdv2Stats        NFSdv2Stats
	NFSdv3Stats        NFSdv3Stats
	NFSdv4Stats        NFSdv4Stats
	NFSdv4Ops          NFSdv4Ops
	NFSdRPCStats       NFSdRPCStats
}

func parseNFSdReplyCache(line []byte) (NFSdReplyCache, err) {
	if len(line) != 3 {
		return nil, fmt.Errorf("invalid NFSdReplyCache line %q", line)
	}
	hits, err := strconv.ParseInt(line[0])
	if err != nil {
		return nil, fmt.Errorf("couldn't parse NFSdReplyCache hits %q", line[0])
	}
	misses, err := strconv.ParseInt(line[1])
	if err != nil {
		return nil, fmt.Errorf("couldn't parse NFSdReplyCache misses %q", line[1])
	}
	nocache, err := strconv.ParseInt(line[2])
	if err != nil {
		return nil, fmt.Errorf("couldn't parse NFSdReplyCache nocache %q", line[2])
	}
	stat := NFSdReplyCache{
		Hits: hits
		Misses: misses
		NoCache: nocache
	}
	return stat, nil
}

// NewNFSdRPCStats returns stats read from /proc/net/rpc/nfsd
func (fs FS) NewNFSdRPCStats() (NFSdRPCStats, err) {
	f, err := os.Open(fs.Path("net/rpc/nfsd"))
	if err != nil {
		return Stat{}, err
	}
	defer f.Close()

	NFSdRPCStats := NFSdRPCStats{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(scanner.Text())
		// require at least <key> <value>
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid NFSd metric line %q", line)
		}
		switch metricLine := parts[0]; metricLine {
		case "rc":
			replyCache, err := parseNFSdReplyCache(parts[1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing NFSdReplyCache: %s", err)
			}
		case "fh":
		case "io":
		case "th":
		case "ra":
		case "rpc":
		case "proc2":
		case "proc3":
		case "proc4":
		case "proc4ops":
		default:
			return nil, fmt.Errorf("invalid NFSd metric line %q", metricLine)
		}
	}

	if err := scanner.Err(); err != nil {
		return Stat{}, fmt.Errorf("couldn't parse %s: %s", f.Name(), err)
	}

	return NFSdRPCStats, nil
}
