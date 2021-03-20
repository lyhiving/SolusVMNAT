package main

import (
	"PortForwardGo/zlog"
	"net"
	"strings"

	proxyprotocol "github.com/pires/go-proxyproto"
)

var https_index map[string]string

func HttpsInit() {
	https_index = make(map[string]string)
	zlog.Info("[HTTPS] Listening ", Setting.Config.Listen["Https"].Port)
	l, err := net.Listen("tcp", ":"+Setting.Config.Listen["Https"].Port)
	if err != nil {
		zlog.Error("[HTTPS] Listen failed , Error: ", err)
		return
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go https_handle(c)
	}
}

func LoadHttpsRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	zlog.Info("Loaded [", i, "] (HTTPS)", r.Listen, " => ", r.Forward)
	https_index[strings.ToLower(r.Listen)] = i

}

func DeleteHttpsRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	zlog.Info("Deleted [", i, "] (HTTPS)",r.Listen, " => ", r.Forward)
	delete(https_index, strings.ToLower(r.Listen))

	Setting.Rules.Lock()
	delete(Setting.Config.Rules, i)
	Setting.Rules.Unlock()
}

func https_handle(conn net.Conn) {
	firstByte := make([]byte, 1)
	_, error := conn.Read(firstByte)
	if error != nil {
		conn.Close()
		return
	}
	if firstByte[0] != 0x16 {
		conn.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, error = conn.Read(versionBytes)
	if error != nil {
		conn.Close()
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		conn.Close()
		return
	}

	restLengthBytes := make([]byte, 2)
	_, error = conn.Read(restLengthBytes)
	if error != nil {
		conn.Close()
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, error = conn.Read(rest)
	if error != nil {
		conn.Close()
		return
	}

	current := 0
	if len(rest) == 0 {
		conn.Close()
		return
	}
	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		conn.Close()
		return
	}

	current += 3
	current += 2
	current += 4 + 28
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		conn.Close()
		return
	}

	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				conn.Close()
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = strings.ToLower(string(rest[current : current+nameLen]))
		}

		current += extensionDataLength
	}

	if hostname == "" {
		conn.Close()
		return
	}

	i, ok := https_index[hostname]
	if !ok {
		conn.Close()
		return
	}

	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	if r.Status != "Active" && r.Status != "Created" {
		conn.Close()
		return
	}

	proxy, error := net.Dial("tcp", r.Forward)
	if error != nil {
		conn.Close()
		return
	}

	if r.ProxyProtocolVersion != 0 {
		header, err := proxyprotocol.HeaderProxyFromAddrs(byte(r.ProxyProtocolVersion), conn.RemoteAddr(), conn.LocalAddr()).Format()
		if err == nil {
			proxy.Write(header)
		}
	}

	proxy.Write(firstByte)
	proxy.Write(versionBytes)
	proxy.Write(restLengthBytes)
	proxy.Write(rest)

	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}
