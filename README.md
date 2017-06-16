## go-dns-shooter

#### 

1. 下载方式

```
  go get github.com/zhangmingkai4315/go-dns-shooter
  ./go-dns-shooter [参数列表]
  
```  

2. 参数列表

```shell

  -domain string
        domain string,for example google.com (default "jsmean.com")
  -max int
        max packets to send (default 100)
  -qps int
        query per second (default 10)
  -randomlen int
        random length of subdomain, for example 5 means *****.google.com (default 5)
  -randomtype
        random dns type to send
  -server string
        dns server and listen port (default "localhost:10053")
  -timeout int
        stop dns shooter until timeout

```