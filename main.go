package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
)

type HandleParam struct {
	c net.Conn
	p string
	a net.IP
}

var paramPool = sync.Pool{
	New: func() interface{} {
		return new(HandleParam)
	},
}

func releaseParam(p *HandleParam) {
	p.c = nil
	p.p = ""
	paramPool.Put(p)
}

func acquireParam(addr, port string, conn net.Conn) *HandleParam {
	p := paramPool.Get().(*HandleParam)
	p.a = net.ParseIP(addr)
	p.p = port
	p.c = conn
	return p
}

type HandleBackParam struct {
	l net.Conn
	r net.Conn
}

var backParamPool = sync.Pool{
	New: func() interface{} {
		return new(HandleBackParam)
	},
}

func releaseBackParam(p *HandleBackParam) {
	p.l = nil
	p.r = nil
	backParamPool.Put(p)
}

func acquireBackParam(port int) *HandleBackParam {
	p := backParamPool.Get().(*HandleBackParam)
	return p
}

// copy from remote to local
func handleBack(_p interface{}) {
	p := _p.(*HandleBackParam)
	r := p.r
	l := p.l
	defer func() {
		time.Sleep(time.Second)
		r.Close()
		l.Close()
	}()
	releaseBackParam(p)
	buf := make([]byte, 1024)
	var n, n2 int
	var err error
	for {
		r.SetReadDeadline(time.Now().Add(remoteRWDeadline))
		n, err = r.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println("Read remote:", err)
			}
			break
		}
		buf = buf[:n]
		l.SetWriteDeadline(time.Now().Add(localRWDeadline))
		n2, err = l.Write(buf)
		if err != nil {
			if err != io.EOF {
				log.Println("Write local:", err)
			}
			break
		}
		if n != n2 {
			log.Println("Read remote != Write local")
			break
		}
	}
}

func isLocalLoop(rhostname, rport string, addr net.IP, lport string) bool {
	if rport != lport {
		return false
	}
	ips, err := net.LookupIP(rhostname)
	if err != nil {
		return true
	}
	for _, rip := range ips {
		if rip.Equal(addr) {
			return true
		}
	}
	return false
}

var tcpDialer = &net.Dialer{
	Timeout:   localRWDeadline,
	DualStack: true,
}
var tlsDialer = &tls.Dialer{
	NetDialer: tcpDialer,
}

var hostUcword = []byte("\nHost:")
var hostLower = []byte("\nhost:")

func forwardTCP(hostname, port string, initData []byte, laddr net.IP, l net.Conn) net.Conn {
	hostname, portStr, err := splitHostnameDefaultPort(hostname, port)
	if err != nil {
		log.Println(err)
		return nil
	}

	// check is local
	if isLocalLoop(hostname, port, laddr, portStr) {
		log.Println("Local connect loop")
		return nil
	}

	// connect tcp to remote
	log.Println("Forward TCP: [" + hostname + "]:" + portStr)
	r, err := tcpDialer.Dial("tcp", "["+hostname+"]:"+portStr)
	if err != nil {
		log.Println("Connect remote:", err)
		return nil
	}

	// write data
	r.SetWriteDeadline(time.Now().Add(localRWDeadline))
	n, err := r.Write(initData)
	if err != nil {
		log.Println("Write init remote:", err)
		return nil
	}
	if n != len(initData) {
		log.Println("Write init remote not")
		return nil
	}
	// continue through
	bp := backParamPool.Get().(*HandleBackParam)
	bp.r = r
	bp.l = l
	err = handleBackPool.Invoke(bp)
	if err != nil {
		log.Println(err)
		return nil
	}
	return r
}

var localRWDeadline = 5 * time.Second
var remoteRWDeadline = 120 * time.Second

func handle(_p interface{}) {
	p := _p.(*HandleParam)
	l := p.c // local
	defer func() {
		time.Sleep(localRWDeadline)
		l.Close()
	}()
	port := p.p
	addr := p.a
	releaseParam(p)
	buf := make([]byte, 1024)
	var n, n2 int
	var err error
	var continueData []byte
	var finished, isTLS, justForward bool
	var hostname string
	var r net.Conn // remote
	for {
		l.SetReadDeadline(time.Now().Add(remoteRWDeadline))
		n, err = l.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println("Local read:", err)
			}
			break
		}
		buf = buf[:n]
		if justForward {
			r.SetWriteDeadline(time.Now().Add(localRWDeadline))
			n2, err = r.Write(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("Remote write:", err)
				}
				break
			}
			if n != n2 {
				log.Println("Remote write != Local read")
				break
			}
			continue
		}
		var data []byte
		if continueData == nil {
			data = buf
		} else {
			data = continueData
		}
		finished, isTLS, hostname, _ = ParseTLSHelloPhrase(data)
		if finished {
			justForward = true
			if isTLS {
				log.Println("SNI:", hostname)
				r = forwardTCP(hostname, port, data, addr, l)
				if r == nil {
					break
				}
				// TODO: handshake local, connect tls to remote :))))))))))))) hihi
			} else {
				// No TLS, parse http hostname
				if len(data) < 8 {
					log.Println("Host dpi?", b2s(data))
					break
				}
				idx := bytes.Index(data, hostUcword)
				if idx == -1 {
					idx = bytes.Index(data, hostLower)
				}
				if idx == -1 {
					// No host header
					log.Println("Hostname not found or dpi?:", b2s(data))
					break
				}
				host := data[idx+6:]
				idx = bytes.IndexByte(host, '\n')
				if idx == -1 {
					log.Println("Hostname not complete or dpi", b2s(data))
					break
				}
				r = forwardTCP(strings.Trim(string(host[:idx]), "\r\n\t "), port, data, addr, l)
				if r == nil {
					break
				}
			}
			continueData = nil
			continue
		}
		if continueData == nil {
			continueData = make([]byte, n)
			copy(continueData, buf)
		} else {
			continueData = append(continueData, buf...)
		}
	}
}

var handleBackPool *ants.PoolWithFunc

func main() {
	if len(os.Args) == 1 {
		log.Println("Usage:", os.Args[0], " [ports..]")
		return
	}
	handlePool, err := ants.NewPoolWithFunc(100, handle)
	if err != nil {
		log.Panicln(err)
	}
	defer handlePool.Release()
	handleBackPool, err = ants.NewPoolWithFunc(100, handleBack)
	if err != nil {
		log.Panicln(err)
	}
	defer handleBackPool.Release()

	hangup := make(chan struct{})
	var hangupFlag uint32
	var haveServer int32
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		log.Panicln("No interfaces:", err)
	}
	for _, iface := range ifaces {
		addr := iface.String()
		idx := strings.LastIndexByte(addr, '/')
		var srvAddr string
		if idx == -1 {
			srvAddr = addr
		} else {
			srvAddr = addr[:idx]
		}
		for _, portStr := range os.Args[1:] {
			_, err = strconv.Atoi(portStr)
			if err != nil {
				log.Println("Invalid port:", portStr)
				continue
			}
			go func(portStr string) {
				defer func() {
					if atomic.CompareAndSwapUint32(&hangupFlag, 0, 1) {
						close(hangup)
					}
				}()
				atomic.AddInt32(&haveServer, 1)
				defer atomic.AddInt32(&haveServer, -1)
				ln, err := net.Listen("tcp", "["+srvAddr+"]:"+portStr)
				if err != nil {
					log.Println("Server:", err)
					return
				}
				log.Println("Server is at:", ln.Addr())
				for {
					conn, err := ln.Accept()
					if err == nil {
						handlePool.Invoke(acquireParam(srvAddr, portStr, conn))
					} else {
						log.Println(err)
					}
				}
			}(portStr)
		}
	}
	time.Sleep(2 * time.Second)
	<-hangup
	if atomic.LoadInt32(&haveServer) != 0 {
		select {}
	}
}
