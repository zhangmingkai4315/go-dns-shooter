package dns

// DefaultServer is the recusive server for dns query
const DefaultServer = "8.8.8.8:53"

const (
	// valid RR_Header.Rrtype and Question.qtype
	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41 // EDNS
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
	TypeAVC        uint16 = 258

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// valid Question.Qtype only
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeReserved uint16 = 65535

	// valid Question.Qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes.
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
	RcodeYXDomain       = 6
	RcodeYXRrset        = 7
	RcodeNXRrset        = 8
	RcodeNotAuth        = 9
	RcodeNotZone        = 10
	RcodeBadSig         = 16 // TSIG
	RcodeBadVers        = 16 // EDNS0
	RcodeBadKey         = 17
	RcodeBadTime        = 18
	RcodeBadMode        = 19 // TKEY
	RcodeBadName        = 20
	RcodeBadAlg         = 21
	RcodeBadTrunc       = 22 // TSIG
	RcodeBadCookie      = 23 // DNS Cookies

	// Message Opcodes. There is no 3.
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
	OpcodeNotify = 4
	OpcodeUpdate = 5
)

const (
	headerSize = 12
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authticated data
	_CD = 1 << 4  // checking disabled
)
