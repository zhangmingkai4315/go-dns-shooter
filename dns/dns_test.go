package dns

import "testing"

func TestSetQuestion(t *testing.T) {
	packet := new(DNSPacket)
	domain := "github.com"
	packet.SetQuestion(FqdnFormat(domain), TypeA)
	if packet.Questions != 1 {
		t.Errorf("%d: expected, Got %d", 1, packet.Questions)
	}
	if len(packet.Question) != 1 {
		t.Errorf("%d: expected, Got %d", 1, len(packet.Question))
	}
	if !packet.Header.RecursionDesired {
		t.Errorf("%v: expected, Got %v", true, packet.Header.RecursionDesired)
	}
	if packet.Question[0].Qtype != TypeA {
		t.Errorf("%v: expected, Got %v", TypeA, packet.Question[0].Qtype)
	}

}

func TestToBytes(t *testing.T) {
	packet := new(DNSPacket)
	domain := "github.com"
	packet.SetQuestion(domain, TypeA)
	rawPacket, err := packet.ToBytes()
	if err != nil {
		t.Errorf("%v: expected, Got %v", nil, err)
	}
	expect := []byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 103, 105, 116, 104, 117, 98, 3, 99, 111, 109, 0, 0, 1, 0, 1}
	if !ByteSliceCompare(rawPacket[2:], expect) {
		t.Errorf("%v: expected, Got %v", rawPacket, nil)
	}
}

func TestUpdateSubDomainToBytes(t *testing.T) {
	packet := new(DNSPacket)
	domain := "github.com"
	packet.SetQuestion(domain, TypeA)
	rawPacket, err := packet.ToBytes()
	if err != nil {
		t.Errorf("%v: expected, Got %v", nil, err)
	}
	packet.UpdateSubDomainToBytes("hithub.com")
	expect := []byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 104, 105, 116, 104, 117, 98, 3, 99, 111, 109, 0, 0, 1, 0, 1}
	if !ByteSliceCompare(rawPacket[2:], expect) {
		t.Errorf("%v: expected, Got %v", rawPacket, nil)
	}
}
