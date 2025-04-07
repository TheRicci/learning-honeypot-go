package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Timestamp time.Time
	IP        string
	Port      int
	Payload   string
	Session   []string
	Duration  time.Duration
}

type Honeypot struct {
	ports    []int
	events   chan Event
	logMutex sync.RWMutex
	ipLog    map[string]int
	history  []Event
}

func NewHoneypot(ports []int) *Honeypot {
	return &Honeypot{
		ports:   ports,
		events:  make(chan Event, 100),
		ipLog:   make(map[string]int),
		history: []Event{},
	}
}

func (hp *Honeypot) Start() {
	for _, port := range hp.ports {
		if port == 21 {
			go hp.listenFTP(port)
		} else {
			go hp.listenOnPort(port)
		}
	}
	go hp.eventLogger()
}

func (hp *Honeypot) listenOnPort(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("[!] Error listening on port %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] Listening on port %d\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go hp.handleConnection(conn, port)
	}
}

func (hp *Honeypot) handleConnection(conn net.Conn, port int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := reader.ReadString('\n')

	hp.events <- Event{
		Timestamp: time.Now(),
		IP:        ip,
		Port:      port,
		Payload:   data,
	}
}

func (hp *Honeypot) listenFTP(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("[!] Error listening on FTP port %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] FTP honeypot listening on port %d\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go hp.handleFTPSession(conn, port)
	}
}

func (hp *Honeypot) handleFTPSession(conn net.Conn, port int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	start := time.Now()
	session := []string{}

	conn.Write([]byte("220 Welcome to MyFTP Server\r\n"))
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		session = append(session, line)

		if strings.ToUpper(line) == "QUIT" {
			conn.Write([]byte("221 Goodbye.\r\n"))
			break
		} else {
			conn.Write([]byte("500 Unknown command.\r\n"))
		}
	}
	duration := time.Since(start)

	hp.events <- Event{
		Timestamp: start,
		IP:        ip,
		Port:      port,
		Payload:   "FTP session",
		Session:   session,
		Duration:  duration,
	}
}

func (hp *Honeypot) eventLogger() {
	for {
		select {
		case evt := <-hp.events:
			hp.logMutex.Lock()
			hp.ipLog[evt.IP]++
			hp.history = append(hp.history, evt)
			hp.logMutex.Unlock()

			fmt.Printf("[LOG] %s - %s:%d > %s\n",
				evt.Timestamp.Format(time.RFC3339), evt.IP, evt.Port, evt.Payload)
			if len(evt.Session) > 0 {
				fmt.Printf("[SESSION from %s] Duration: %s\n", evt.IP, evt.Duration)
				for _, cmd := range evt.Session {
					fmt.Printf("\t> %s\n", cmd)
				}
			}
		}
	}
}

func main() {
	hp := NewHoneypot([]int{21, 22, 80})
	hp.Start()

	select {} // Block forever
}
