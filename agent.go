package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sync"
)


var serverAddr string
var agentMode string

const xor byte = 0x64

/*Tunnel 代理隧道*/
type Tunnel struct {
	clientConn net.Conn
	serverConn net.Conn
	connWait   sync.WaitGroup
}

func newTunnel(c net.Conn) *Tunnel {
	t := new(Tunnel)
	t.clientConn = c
	t.connWait.Add(2)

	return t
}

func main() {
	var listenAddr string

	flag.StringVar(&serverAddr, "s", "192.168.222.131:1080", "server agent addr default (192.168.222.131:1080)")
	flag.StringVar(&listenAddr, "l", "0.0.0.0:1080", "listen addr default (0.0.0.0:1080)")
	flag.StringVar(&agentMode, "m", "client", "agent mode default (client)")
	flag.Parse()

	var listen net.Listener
	var err error
	listen, err = net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println("error listening:", err)
		os.Exit(1)
	}
	defer listen.Close()
	fmt.Printf("run mode %s listening on %s\n", agentMode, listenAddr)
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println("error accepting: ", err)
			os.Exit(1)
		}

		t := newTunnel(conn)
		if agentMode == "client" {
			go processClientShake(t)
		} else {
			go processServerShake(t)
		}
	}
}

func processClientShake(t *Tunnel) {
	defer func() {
		t.clientConn.Close()
		if t.serverConn != nil {
			t.serverConn.Close()
		}

		if err := recover(); err != nil {
			fmt.Printf("panic: %v\n\n%s", err, debug.Stack())
		}
	}()

	var err error
	var recvBuf [64]byte
	// 接收第一次握手信息
	_, err = io.ReadFull(t.clientConn, recvBuf[0:3])
	if err != nil {
		fmt.Println("Read error ", err.Error())
		return
	}

	if recvBuf[0] != 0x05 || recvBuf[1] != 0x01 || recvBuf[2] != 0x00 {
		fmt.Println("Invalid socks5 format")
		return
	}

	// 发送第一次握手应答
	var sendBuf [64]byte
	sendBuf[0] = 0x05
	sendBuf[1] = 0x00
	_, err = t.clientConn.Write(sendBuf[0:2])
	if err != nil {
		fmt.Println("Write error ", err.Error())
		return
	}

	// 接收第二次握手信息
	_, err = io.ReadFull(t.clientConn, recvBuf[0:4])
	if err != nil {
		fmt.Println("Read error ", err.Error())
		return
	}

	var sendLen int
	sendBuf[0] = 0x05
	sendBuf[1] = 0x00
	sendBuf[2] = 0x00
	sendBuf[3] = recvBuf[3]

	var textAddr string
	ATYPE := recvBuf[3]
	if ATYPE == 0x01 {
		_, err := io.ReadFull(t.clientConn, recvBuf[4:10])
		if err != nil {
			fmt.Println("Read error ", err.Error())
			return
		}

		port := binary.BigEndian.Uint16(recvBuf[8:10])
		textAddr = fmt.Sprintf("%d.%d.%d.%d:%d", recvBuf[4], recvBuf[5], recvBuf[6], recvBuf[7], port)

		copy(sendBuf[4:], recvBuf[4:10])

		sendLen = 10

	} else if ATYPE == 0x03 {
		_, err = io.ReadFull(t.clientConn, recvBuf[4:5])
		if err != nil {
			fmt.Println("Read error ", err.Error())
			return
		}
		domainLen := recvBuf[4]
		_, err = io.ReadFull(t.clientConn, recvBuf[5:5+domainLen+2])
		if err != nil {
			fmt.Println("Read error ", err.Error())
			return
		}
		port := binary.BigEndian.Uint16(recvBuf[5+domainLen : 5+domainLen+2])
		textAddr = fmt.Sprintf("%s:%d", string(recvBuf[5:5+recvBuf[4]]), port)

		copy(sendBuf[4:], recvBuf[4:4+domainLen+3])

		sendLen = int(domainLen + 7)
	}

	// 发送第二次握手应答
	_, err = t.clientConn.Write(sendBuf[0:sendLen])
	if err != nil {
		fmt.Println("Write error ", err.Error())
		return
	}

	fmt.Printf("shake sucessful %v %s\n", t.clientConn.RemoteAddr(), textAddr)

	serverConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("Dial error ", err.Error())
		return
	}

	t.serverConn = serverConn

	// 发消息给服务器
	sendBuf[0] = byte(len(textAddr))
	for i := 0; i < len(textAddr); i++ {
		sendBuf[i+1] = textAddr[i] ^ xor
	}
	_, err = t.serverConn.Write(sendBuf[:len(textAddr)+1])
	if err != nil {
		fmt.Println("Write error ", err.Error())
		return
	}

	go processRecv(t)
	go processSend(t)

	t.connWait.Wait()
}

func processServerShake(t *Tunnel) {
	defer func() {
		t.clientConn.Close()
		if t.serverConn != nil {
			t.serverConn.Close()
		}

		if err := recover(); err != nil {
			fmt.Printf("panic: %v\n\n%s", err, debug.Stack())
		}
	}()

	var err error
	var recvBuf [64]byte
	// 接收第一次握手信息
	_, err = io.ReadFull(t.clientConn, recvBuf[0:1])
	if err != nil {
		fmt.Println("Read error ", err.Error())
		return
	}
	addrLen := int(recvBuf[0])
	_, err = io.ReadFull(t.clientConn, recvBuf[1:1+addrLen])
	if err != nil {
		fmt.Println("Read error ", err.Error())
		return
	}
	for i := 0; i < addrLen; i++ {
		recvBuf[i+1] = recvBuf[i+1] ^ xor
	}

	targetAddr := string(recvBuf[1 : 1+addrLen])
	fmt.Printf("shake sucessful %v %s\n", t.clientConn.RemoteAddr(), targetAddr)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Println("Dial error ", err.Error())
		return
	}

	t.serverConn = targetConn

	go processRecv(t)
	go processSend(t)

	t.connWait.Wait()
}

func processSend(t *Tunnel) {

	var recvBuf [1024]byte
	for {
		n, err := t.clientConn.Read(recvBuf[:])
		if err != nil {
			fmt.Println("Read error ", err.Error())
			break
		}

		// 加密
		for i := 0; i < n; i++ {
			recvBuf[i] = recvBuf[i] ^ xor
		}

		_, err = t.serverConn.Write(recvBuf[:n])
		if err != nil {
			fmt.Println("Write error ", err.Error())
			break
		}
	}

	t.connWait.Done()
}

func processRecv(t *Tunnel) {

	var recvBuf [1024]byte
	for {
		n, err := t.serverConn.Read(recvBuf[:])
		if err != nil {
			fmt.Println("Read error ", err.Error())
			break
		}

		// 解密
		for i := 0; i < n; i++ {
			recvBuf[i] = recvBuf[i] ^ xor
		}

		_, err = t.clientConn.Write(recvBuf[:n])
		if err != nil {
			fmt.Println("Write error ", err.Error())
			break
		}
	}

	t.connWait.Done()
}
