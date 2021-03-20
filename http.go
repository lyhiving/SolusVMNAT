package main

import (
	"SolusVMNAT/zlog"
	"bufio"
	"container/list"
	"net"
	"strings"

	proxyprotocol "github.com/pires/go-proxyproto"
)

var http_index map[string]string

func HttpInit() {
	http_index = make(map[string]string)
	zlog.Info("[HTTP] Listening ", Setting.Config.Listen["Http"].Port)
	l, err := net.Listen("tcp", ":"+Setting.Config.Listen["Http"].Port)
	if err != nil {
		zlog.Error("[HTTP] Listen failed , Error: ", err)
		return
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go http_handle(c)
	}
}

func LoadHttpRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	zlog.Info("Loaded [", i, "] (HTTPS)", r.Listen, " => ", r.Forward)
	http_index[strings.ToLower(r.Listen)] = i
}

func DeleteHttpRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()
	
	zlog.Info("Deleted [", i, "] (HTTP)", r.Listen, " => ", r.Forward)
	delete(http_index, strings.ToLower(r.Listen))
	Setting.Rules.Lock()
	delete(Setting.Config.Rules, i)
	Setting.Rules.Unlock()
}

func http_handle(conn net.Conn) {
	headers := bufio.NewReader(conn)
	hostname := ""
	readLines := list.New()
	for {
		bytes, _, error := headers.ReadLine()
		if error != nil {
			conn.Close()
			return
		}
		line := string(bytes)
		readLines.PushBack(line)

		if line == "" {
			break
		}

		if strings.HasPrefix(line, "X-Forward-For: ") == false {
			readLines.PushBack("X-Forward-For: " + ParseAddrToIP(conn.RemoteAddr().String()))
		}

		if strings.HasPrefix(line, "Host: ") {
			hostname = ParseHostToName(strings.TrimPrefix(line, "Host: "))
		}
	}

	if hostname == "" {
		conn.Write([]byte(HttpStatus(503)))
		conn.Write([]byte("\n"))
		conn.Write([]byte(Page503))
		conn.Close()
		return
	}

	i, ok := http_index[hostname]
	if !ok {
		conn.Write([]byte(HttpStatus(503)))
		conn.Write([]byte("\n"))
		conn.Write([]byte(Page503))
		conn.Close()
		return
	}

	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	if r.Status != "Active" && r.Status != "Created" {
		conn.Write([]byte(HttpStatus(503)))
		conn.Write([]byte("\n"))
		conn.Write([]byte(Page503))
		conn.Close()
		return
	}

	proxy, error := net.Dial("tcp", r.Forward)
	if error != nil {
		conn.Write([]byte(HttpStatus(522)))
		conn.Write([]byte("\n"))
		conn.Write([]byte(Page522))
		conn.Close()
		return
	}

	if r.ProxyProtocolVersion != 0 {
		header, err := proxyprotocol.HeaderProxyFromAddrs(byte(r.ProxyProtocolVersion), conn.RemoteAddr(), conn.LocalAddr()).Format()
		if err == nil {
			proxy.Write( header)
		}
	}

	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		proxy.Write([]byte(line))
		proxy.Write( []byte("\n"))
	}

	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}

func ParseAddrToIP(addr string) string {
	var str string
	arr := strings.Split(addr, ":")
	for i := 0; i < (len(arr) - 1); i++ {
		if i != 0 {
			str = str + ":" + arr[i]
		} else {
			str = str + arr[i]
		}
	}
	return str
}

func ParseHostToName(host string) string {
	if strings.Index(host, ":") == -1 {
		return strings.ToLower(host)
	} else {
		return strings.ToLower(strings.Split(host, ":")[0])
	}
}
