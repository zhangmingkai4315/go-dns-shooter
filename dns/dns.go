package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// DNSHeader holds a DNS Header.
type DNSHeader struct {
	ID                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

// RawHeader is the wire format for the DNS packet header.
type RawHeader struct {
	ID                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), errors.New("overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func (dh *RawHeader) pack(msg []byte, off int) (int, error) {
	off, err := packUint16(dh.ID, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Bits, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Qdcount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Ancount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Nscount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Arcount, msg, off)
	return off, err
}

// Question holds a DNS question. There can be multiple questions in the
// question section of a message. Usually there is just one.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func (question *Question) pack(msg []byte, offset int, rawpack []byte) (int, error) {
	for i, v := range rawpack {
		msg[offset+i] = v
	}
	offset += len(rawpack)
	offset, err := packUint16(question.Qtype, msg, offset)
	if err != nil {
		return offset, err
	}
	offset, err = packUint16(question.Qclass, msg, offset)
	if err != nil {
		return offset, err
	}
	return offset, nil
}

// RR is a interface for any dns resource record.
// type RR interface {
// 	Header() *RRHeader
// 	String() string
// 	pack([]byte, int, map[string]int, bool) (int, error)
// }

// RRHeader is the header of dns record.
// type RRHeader struct {
// 	Name         string
// 	RRType       uint16
// 	Class        uint16
// 	TTL          uint32
// 	RRDataLength uint16
// }

// DNSPacket holds a DNS packet
type DNSPacket struct {
	Header         DNSHeader
	Questions      uint16
	Answers        uint16
	AuthorityRRs   uint16
	AdditionRRs    uint16
	Question       []Question // Holds the RR(s) of the question section.
	RawByte        []byte
	init           bool
	lock           sync.Mutex
	RandomLength   int
	RandomType     bool
	OriginalDomain string
}

// SetQuestion will set the basic dns packet infomation
func (dns *DNSPacket) SetQuestion(name string, dnstype uint16) *DNSPacket {
	dns.Header.ID = GenerateRandomID(true)
	dns.Header.RecursionDesired = true
	dns.Questions = 1
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{name, dnstype, ClassINET}
	return dns
}

// ToBytes will generate the first raw bytes of the dns packet
func (dns *DNSPacket) ToBytes() (msg []byte, err error) {
	var rawheader RawHeader
	header := dns.Header
	rawheader.ID = header.ID
	rawheader.Bits = uint16(header.Opcode)<<11 | uint16(header.Rcode)
	if header.Response {
		rawheader.Bits |= _QR
	}
	if header.Authoritative {
		rawheader.Bits |= _AA
	}
	if header.Truncated {
		rawheader.Bits |= _TC
	}
	if header.RecursionDesired {
		rawheader.Bits |= _RD
	}
	if header.RecursionAvailable {
		rawheader.Bits |= _RA
	}
	if header.Zero {
		rawheader.Bits |= _Z
	}
	if header.AuthenticatedData {
		rawheader.Bits |= _AD
	}
	if header.CheckingDisabled {
		rawheader.Bits |= _CD
	}
	question := dns.Question
	rawheader.Qdcount = uint16(len(question))
	offset := 0
	formatName := PackDomainName(FqdnFormat(question[0].Name))
	packLen := 12 + len(formatName) + 4
	msg = make([]byte, packLen)

	offset, err = rawheader.pack(msg, offset)
	if err != nil {
		return nil, err
	}
	offset, err = dns.Question[0].pack(msg, offset, formatName)
	if err != nil {
		return nil, err
	}
	dns.RawByte = msg[:offset]
	dns.init = true
	return msg[:offset], nil
}

// UpdateSubDomainToBytes function update the packet []byte with the new domain name
// and return the new raw data
func (dns *DNSPacket) UpdateSubDomainToBytes(domain string) (msg []byte, err error) {
	// Get a new ID for packet
	id := GenerateRandomID(true)
	packUint16(id, dns.RawByte, 0)
	rawByte := dns.RawByte[:]
	if len(rawByte) > 0 && dns.init == true {
		formatName := PackDomainName(FqdnFormat(domain))
		for i, v := range formatName {
			rawByte[12+i] = v
		}
		if dns.RandomType {
			offset := 12 + len(formatName)
			packUint16(GenRandomType(), rawByte, offset)
			// dns.RawByte[] = GenRandomType()
		}
		return rawByte, nil
	}
	return nil, errors.New("Please call ToBytes() before generate more packet")
}

// GeneratePacket will generate dns packet based user input arguments.
// Arguments
// 		domain: the dns domain name, if you want generate ***.jsmean.com. please fill domain=jsmean.com
//  	length: the random subdomain length.
// 		total: the total number of the dns packet ,if total == 0 no total limit (query)
// 		timeout: shutdown when timeout, if timeout == 0 ,no timeout limit (second)
//      qps: query per second
func (dns *DNSPacket) GeneratePacket(server string, total int, timeout int, qps int) uint32 {
	var (
		wg                sync.WaitGroup
		MaxProducerNumber int
		ticker            *time.Ticker
		counter           uint32
		jumpOut           bool
		throttle          chan struct{}
		// socketChannel     chan []byte
	)
	if server == "" {
		server = DefaultServer
	}
	ticker = time.NewTicker(time.Second)
	if runtime.NumCPU() == 1 {
		MaxProducerNumber = 1
	}
	// 仅仅使用一半的服务器cpu资源
	MaxProducerNumber = int(runtime.NumCPU() / 2)
	log.Printf("From main goroutine fork %d sub goroutine for generate\n", MaxProducerNumber)

	wg.Add(MaxProducerNumber)
	if qps != 0 && qps > 0 {
		throttle = make(chan struct{}, qps)
		qpsTicker := time.NewTicker(time.Second)
		go func() {
			for {
				select {
				case <-qpsTicker.C:
					for i := 0; i < qps; i++ {
						throttle <- struct{}{}
					}
				}
			}
		}()
	}
	if timeout != 0 && timeout > 0 {
		timerTimeout := time.NewTimer(time.Second * time.Duration(timeout))
		go func() {
			<-timerTimeout.C
			jumpOut = true
		}()
	}

	// This goroutine will do statics work.
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Printf("Current goroutine number %d [send:%d query]\n", runtime.NumGoroutine(), atomic.LoadUint32(&counter))
			}
		}
	}()

	length := dns.RandomLength
	domain := dns.OriginalDomain
	for p := 0; p < MaxProducerNumber; p++ {

		conn, err := net.Dial("udp", server)
		log.Printf("Open a connection to dns server[%s]\n", server)

		go func() {
			for {
				data := make([]byte, 1024)
				_, err = conn.Read(data)
				if err != nil {
					fmt.Printf("Fail to read udp message:%v\n", err)
					continue
				}
			}
		}()

		go func() {
			if err != nil {
				fmt.Println(err)
			}
			if total == 0 {
				for {
					if qps != 0 && qps > 0 {
						<-throttle
					}
					randomDomain := GenRandomDomain(length, domain)
					rawByte, err := dns.UpdateSubDomainToBytes(randomDomain)
					if err != nil {
						log.Panicf("%v", err)
					}
					conn.Write(rawByte)
					atomic.AddUint32(&counter, 1)
					if jumpOut == true {
						break
					}
				}
				wg.Done()
			} else {
				eachProduceQueryNum := total / MaxProducerNumber
				for i := 0; i < eachProduceQueryNum; i++ {
					if qps != 0 && qps > 0 {
						<-throttle
					}
					randomDomain := GenRandomDomain(length, domain)
					dns.lock.Lock()
					if _, err := dns.UpdateSubDomainToBytes(randomDomain); err != nil {
						log.Panicf("%v", err)
					}
					conn.Write(dns.RawByte)
					dns.lock.Unlock()
					atomic.AddUint32(&counter, 1)
					if jumpOut == true {
						break
					}
				}
				wg.Done()
			}
		}()
	}
	wg.Wait()
	return counter
}

// InitialPacket initial the basic setup
func (dns *DNSPacket) InitialPacket(domain string, length int, queryType uint16) {
	log.Println("Start generate dns packet")
	dns.SetQuestion(FqdnFormat(GenRandomDomain(length, domain)), queryType)
	dns.ToBytes()
	dns.RandomLength = length
	dns.OriginalDomain = domain
}

// Send will send the dns packet
func (dns *DNSPacket) Send(server string) ([]byte, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		fmt.Println(err)
	}
	conn.Write(dns.RawByte)
	// Close connect asap
	defer conn.Close()
	//simple Read
	buffer := make([]byte, 512)
	conn.Read(buffer)
	return buffer, nil
}
