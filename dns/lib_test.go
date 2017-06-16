package dns

import (
	"reflect"
	"testing"
)

const (
	DOMAIN = "jsmean.com"
	Server = "8.8.8.8"
)

func TestGenRandomDomain(t *testing.T) {
	str := GenRandomDomain(5, DOMAIN)
	if len(str) != 16 {
		t.Errorf("Expect length is 16 but get %d", len(str))
	}
}

func BenchmarkGenRandomDomain(b *testing.B) {

	for i := 0; i < b.N; i++ {
		_ = GenRandomDomain(5, DOMAIN)
	}
}

func TestGenerateRandomID(t *testing.T) {
	var cases = []struct {
		input  bool
		output uint16
	}{
		{
			false,
			uint16(0xfffe),
		},
		{
			true,
			uint16(0),
		},
	}
	for _, test := range cases {
		if test.input == false {
			output := GenerateRandomID(test.input)
			if test.output != output {
				t.Errorf("%v: expected, Got %v", test.output, output)
			}
		} else {
			output := GenerateRandomID(test.input)
			if reflect.TypeOf(output).Kind() != reflect.Uint16 {
				t.Errorf("%v: expected, Got %v", test.output, output)
			}
		}
	}
}

func TestFqdnFormat(t *testing.T) {
	var cases = []struct {
		input  string
		output string
	}{
		{
			"",
			".",
		},
		{
			"abc.com",
			"abc.com.",
		},
		{
			"abc.com.",
			"abc.com.",
		},
	}
	for _, test := range cases {
		output := FqdnFormat(test.input)
		if test.output != output {
			t.Errorf("%v: expected, Got %v", test.output, output)
		}
	}

}

func TestPackDomainName(t *testing.T) {
	var cases = []struct {
		input  string
		output []byte
	}{
		{
			"baidu.com.",
			[]byte{5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0},
		},
		{
			"google.com.",
			[]byte{6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0},
		},
	}
	for _, test := range cases {
		output := PackDomainName(test.input)
		if !ByteSliceCompare(test.output, output) {
			t.Errorf("%v: expected, Got %v", test.output, output)
		}
	}

}
