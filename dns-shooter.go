package main

import (
	"flag"
	"log"
	"time"

	"github.com/zhangmingkai4315/go-dns-shooter/dns"
)

var (
	timeout    int
	max        int
	qps        int
	domain     string
	server     string
	randomlen  int
	randomtype bool
)

func init() {
	flag.IntVar(&timeout, "timeout", 0, "stop dns shooter until timeout")
	flag.IntVar(&max, "max", 100, "max packets to send")
	flag.IntVar(&qps, "qps", 10, "query per second")
	flag.StringVar(&server, "server", "localhost:10053", "dns server and listen port")
	flag.StringVar(&domain, "domain", "jsmean.com", "domain string,for example google.com")
	flag.IntVar(&randomlen, "randomlen", 5, "random length of subdomain, for example 5 means *****.google.com")
	flag.BoolVar(&randomtype, "randomtype", false, "random dns type to send")
}

func main() {
	flag.Parse()
	packet := new(dns.DNSPacket)
	packet.InitialPacket(domain, randomlen, dns.TypeA)
	packet.RandomType = randomtype
	startTime := time.Now()
	counter := packet.GeneratePacket(server, max, timeout, qps)
	log.Printf("Produce %d dns packet in %.2f seconds", counter, time.Since(startTime).Seconds())
}
