package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"

	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type SuricataAlert struct {
	UID       string
	Signature string
	Category  string
	Severity  int
	SrcIP     string
	DestPort  int
	Timestamp time.Time
	EventID   string
}

type Event struct {
	ID           string
	Timestamp    time.Time
	IP           string
	Port         int
	Payload      string
	Session      []string
	Duration     time.Duration
	SuricataData []*SuricataAlert
}

type Honeypot struct {
	ports        []int
	EventMap     map[string]*Event
	eventMutex   sync.RWMutex
	history      []*Event
	suricataJobs chan *Event
	splunkJobs   chan *Event
}

func NewHoneypot(ports []int) *Honeypot {
	hp := &Honeypot{
		ports:        ports,
		EventMap:     make(map[string]*Event),
		history:      []*Event{},
		suricataJobs: make(chan *Event, 100),
		splunkJobs:   make(chan *Event, 100),
	}
	hp.startWorkerPools()
	return hp
}

func (hp *Honeypot) watchSuricataAlerts() {
	const baseDir = "/tmp/suricata-alerts"

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("[!] Failed to create fsnotify watcher:", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(baseDir); err != nil {
		fmt.Println("[!] Error watching directory:", err)
		return
	}

	seen := make(map[string]bool)

	for {
		select {
		case ev := <-watcher.Events:
			if ev.Op&fsnotify.Create == fsnotify.Create {
				name := filepath.Base(ev.Name)
				//fmt.Println(name)
				if strings.HasPrefix(name, "event-") {
					evtID := strings.TrimPrefix(name, "event-")
					if !seen[evtID] {
						subDir := filepath.Join(baseDir, name)
						evePath := filepath.Join(subDir, "eve.json")
						go hp.processEveFile(evtID, evePath)
						seen[evtID] = true
					}
				}
			}

		case err := <-watcher.Errors:
			fmt.Println("[!] fsnotify error:", err)
		}
	}
}

func (hp *Honeypot) processEveFile(evtID, evePath string) {
	time.Sleep(1 * time.Second)
	// Open once and keep track of how far we've read
	f, err := os.Open(evePath)
	if err != nil {
		fmt.Printf("[!] failed to open eve.json (%s): %v\n", evePath, err)
		return
	}
	defer f.Close()

	// Start at beginning
	var offset int64
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("[!] fsnotify error:", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(evePath); err != nil {
		fmt.Println("[!] fsnotify add error:", err)
		return
	}

	buf := bufio.NewReader(f)
	for {
		select {
		case ev := <-watcher.Events:
			if ev.Op&fsnotify.Write == fsnotify.Write {
				// Seek to last offset
				f.Seek(offset, io.SeekStart)
				// Read all new lines
				for {
					line, err := buf.ReadBytes('\n')
					if err == io.EOF {
						break
					} else if err != nil {
						fmt.Println("[!] read error:", err)
						break
					}
					offset += int64(len(line))

					// Process JSON alert lines as before
					var entry map[string]interface{}
					if err := json.Unmarshal(line, &entry); err != nil {
						continue
					}

					if entry["event_type"] != "alert" {
						continue
					}

					srcIP := entry["src_ip"].(string)
					destPort := int(entry["dest_port"].(float64))
					alertData := entry["alert"].(map[string]interface{})
					signature := alertData["signature"].(string)
					category := alertData["category"].(string)
					severity := int(alertData["severity"].(float64))
					timestampStr := entry["timestamp"].(string)

					t, _ := time.Parse(time.RFC3339Nano, timestampStr)

					alert := SuricataAlert{
						Signature: signature,
						Category:  category,
						Severity:  severity,
						SrcIP:     srcIP,
						DestPort:  destPort,
						Timestamp: t,
						EventID:   evtID,
					}

					fmt.Printf("[SURICATA] [EVENT-%s] [%s] %s:%d -> %s (%s, Severity %d)\n",
						alert.EventID,
						alert.Timestamp.Format(time.RFC3339),
						alert.SrcIP,
						alert.DestPort,
						alert.Signature,
						alert.Category,
						alert.Severity,
					)

					fmt.Println("alert", alert)

					hp.eventMutex.Lock()
					hp.EventMap[evtID].SuricataData = append(hp.EventMap[evtID].SuricataData, &alert)
					evt := hp.EventMap[evtID]
					hp.eventMutex.Unlock()
					hp.splunkJobs <- evt
				}
			}

		case err := <-watcher.Errors:
			fmt.Println("[!] fsnotify watcher error:", err)
		}
	}
}

func (hp *Honeypot) listenOnPort(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp4", addr)
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

func (hp *Honeypot) handleConnection(conn net.Conn, port int) { //add start and duration
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := reader.ReadString('\n')

	hp.registerEvent(time.Now(), ip, &data, port, nil)
}

type ftpData struct {
	session  []string
	duration time.Duration
}

func (hp *Honeypot) registerEvent(t time.Time, ip string, payload *string, port int, ftp *ftpData) {
	id := makeEventID(ip, port, t)

	event := Event{
		ID:        id,
		Timestamp: t,
		IP:        ip,
		Port:      port,
	}

	if ftp != nil {
		event.Session = ftp.session
		event.Duration = ftp.duration
	} else {
		event.Payload = *payload
	}

	hp.eventMutex.Lock()
	hp.EventMap[id] = &event
	hp.eventMutex.Unlock()

	fmt.Printf("[LOG] %s - %s:%d > %s\n", event.Timestamp.Format(time.RFC3339), event.IP, event.Port, event.Payload)
	if len(event.Session) > 0 {
		fmt.Printf("[SESSION from %s] Duration: %s\n", event.IP, event.Duration)
		for _, cmd := range event.Session {
			fmt.Printf("\t> %s\n", cmd)
		}
	}

	hp.suricataJobs <- &event
}

func (hp *Honeypot) listenFTPS(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Printf("[!] Error listening on FTPS port %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] FTPS honeypot listening on port %d\n", port)
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

	// Load TLS certificate
	tlsCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("[!] Failed to load TLS certificate:", err)
		return
	}

	// Wrap the connection with TLS
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Println("[!] TLS handshake failed:", err)
		return
	}
	defer tlsConn.Close()

	// Extract IP
	remoteAddr := tlsConn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	start := time.Now()
	session := []string{}

	tlsConn.Write([]byte("220 FTPS Service Ready\r\n"))
	scanner := bufio.NewScanner(tlsConn)
	for scanner.Scan() {
		line := scanner.Text()
		session = append(session, line)

		if strings.ToUpper(line) == "QUIT" {
			tlsConn.Write([]byte("221 Goodbye.\r\n"))
			break
		} else {
			tlsConn.Write([]byte("500 Unknown command.\r\n"))
		}
	}
	duration := time.Since(start)

	hp.registerEvent(start, ip, nil, port, &ftpData{duration: duration, session: session})

}

func (hp *Honeypot) Start() {
	for _, port := range hp.ports {
		switch port {
		case 990:
			go hp.listenFTPS(port)
		case 443:
			go hp.startHTTPHoneypot(port)
		default:
			go hp.listenOnPort(port)
		}
	}
	go hp.watchSuricataAlerts()
}

func main() {
	hp := NewHoneypot([]int{443, 990, 22})
	hp.Start()

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	<-sigint
	fmt.Println("Shutting down server...")
}

func (hp *Honeypot) startHTTPHoneypot(port int) {
	mux := http.NewServeMux()

	wrap := func(handler func(http.ResponseWriter, *http.Request) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			info := handler(w, r)
			ip := strings.Split(r.RemoteAddr, ":")[0]

			hp.registerEvent(time.Now(), ip, &info, port, nil)
		}
	}

	mux.HandleFunc("/search", wrap(sqlInjectionBait))
	mux.HandleFunc("/comment", wrap(xssBait))
	mux.HandleFunc("/admin.php", wrap(fakePHPAdmin))
	mux.HandleFunc("/upload", wrap(fakeUpload))
	mux.HandleFunc("/config", wrap(leakConfig))
	mux.HandleFunc("/robots.txt", wrap(serveRobots))
	mux.HandleFunc("/backup.zip", wrap(fakeDownload))
	mux.HandleFunc("/shell.php", wrap(fakeShell))

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	certFile := "cert.pem"
	keyFile := "key.pem"

	// Load certificates
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("[!] Failed to load cert: %v\n", err)
		return
	}

	// Create a TLS config
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// Listen only on IPv4
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Printf("[!] Listen error: %v\n", err)
		return
	}

	// Wrap the listener with TLS
	tlsListener := tls.NewListener(listener, tlsConfig)

	fmt.Println("[*] HTTPS honeypot running on", addr)
	// Start the server
	err = http.Serve(tlsListener, mux)
	if err != nil {
		fmt.Printf("[!] HTTPS server error: %v\n", err)
		return
	}
}

func sqlInjectionBait(w http.ResponseWriter, r *http.Request) string {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "Results for '%s': No results found.", q)
	return fmt.Sprintf("Search query: %s", q)
}

func xssBait(w http.ResponseWriter, r *http.Request) string {
	msg := r.URL.Query().Get("msg")
	fmt.Fprintf(w, "<p>%s</p>", msg)
	return fmt.Sprintf("XSS comment: %s", msg)
}

func fakePHPAdmin(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseForm()
		u := r.FormValue("user")
		p := r.FormValue("pass")
		fmt.Fprintln(w, "Access Denied.")
		return fmt.Sprintf("Admin.php login attempt: %s / %s", u, p)
	}
	fmt.Fprintln(w, `
		<!DOCTYPE html>
		<html>
		<head><title>Admin Login</title></head>
		<body>
			<h2>Admin Panel</h2>
			<form method='POST' action='admin.php'>
				User: <input name='user'/><br/>
				Pass: <input name='pass' type='password'/><br/>
				<input type='submit'/>
			</form>
		</body>
		</html>`)
	return "Admin.php login form served"
}

func fakeUpload(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseMultipartForm(10 << 20)
		file, handler, err := r.FormFile("upload")
		if err == nil {
			file.Close()
			fmt.Fprintln(w, "File received.")
			return fmt.Sprintf("File uploaded: %s (%d bytes)", handler.Filename, handler.Size)
		}
		fmt.Fprintln(w, "Upload failed.")
		return "Upload error"
	}
	fmt.Fprintln(w, "<form method='POST' enctype='multipart/form-data'>File: <input type='file' name='upload'/><br/><input type='submit'/></form>")
	return "Upload form served"
}

func leakConfig(w http.ResponseWriter, r *http.Request) string {
	fmt.Fprintln(w, "DB_PASS=supersecret\nAPI_KEY=12345-ABCDE")
	return "Config file accessed"
}

func serveRobots(w http.ResponseWriter, r *http.Request) string {
	fmt.Fprintln(w, "User-agent: *\nDisallow: /backup\nDisallow: /admin")
	return "robots.txt requested"
}

func fakeDownload(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Disposition", "attachment; filename=backup.zip")
	w.Write([]byte("FAKE_ZIP_CONTENT"))
	return "Backup.zip requested"
}

func fakeShell(w http.ResponseWriter, r *http.Request) string {
	cmd := r.URL.Query().Get("cmd")
	fmt.Fprintf(w, "Output: %s", strings.Repeat("*", len(cmd)))
	return fmt.Sprintf("Web shell command: %s", cmd)
}

func (hp *Honeypot) GeneratePCAPAndRunSuricata(evt *Event) error {
	filename := fmt.Sprintf("%s.pcap", evt.ID)
	pcapPath := filepath.Join("/tmp/pcaps", filename)

	err := WritePCAP(evt, pcapPath)
	if err != nil {
		return fmt.Errorf("error writing pcap: %v", err)
	}

	err = os.Mkdir(fmt.Sprintf("/tmp/suricata-alerts/event-%s", evt.ID), 0777)
	if err != nil {
		return fmt.Errorf("event temp directory creation failed: %v", err)
	}
	cmd := exec.Command("suricata", "-r", pcapPath, "-l", fmt.Sprintf("/tmp/suricata-alerts/event-%s", evt.ID))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("[SURICATA] Running analysis on %s...\n", pcapPath)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("suricata execution failed: %v", err)
	}

	return nil
}

func WritePCAP(evt *Event, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(65536, layers.LinkTypeEthernet)

	srcIP := net.ParseIP(evt.IP)
	if srcIP == nil {
		srcIP = net.IPv4(192, 168, 1, 100)
	}

	dstIP := net.IPv4(192, 168, 1, 10)
	srcPort := layers.TCPPort(12345)
	dstPort := layers.TCPPort(evt.Port)

	// Build the full payload
	raw := evt.Payload
	if len(evt.Session) > 0 {
		raw = strings.Join(evt.Session, "\r\n")
	}

	data := []byte(raw)
	const safeSize = 1400 // ~MTU minus headers

	// Split into chunks and write each as its own packet (no EVENT-ID marker)
	for offset := 0; offset < len(data); {
		end := offset + safeSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]

		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: srcPort,
			DstPort: dstPort,
			Seq:     1105024978,
			SYN:     true,
			ACK:     true,
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(chunk)); err != nil {
			return err
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     evt.Timestamp,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		if err := writer.WritePacket(ci, buf.Bytes()); err != nil {
			return err
		}

		offset = end
	}

	return nil
}

func makeEventID(ip string, port int, t time.Time) string {
	randVal := rand.Intn(1000000) + 1
	seed := fmt.Sprintf("%s|%d|%d|%d", ip, port, t.UnixNano(), randVal)
	h := fnv.New64a()
	h.Write([]byte(seed))
	return fmt.Sprintf("%x", h.Sum64())
}

var hecURL = "https://splunk.example.com:8088/services/collector/event"
var hecToken = "YOUR-HEC-TOKEN"

type hecEvent struct {
	Time       int64       `json:"time"`
	Sourcetype string      `json:"sourcetype"`
	Event      interface{} `json:"event"`
}

func sendToSplunk(evt *Event) error {
	payload := hecEvent{
		Time:       evt.Timestamp.Unix(),
		Sourcetype: "honeypot:event",
		Event:      evt,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", hecURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+hecToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("splunk HEC error: %s", resp.Status)
	}
	return nil
}

func (hp *Honeypot) startWorkerPools() {
	const (
		suricataWorkers = 2
		splunkWorkers   = 3
	)
	// Suricata workers
	for i := 0; i < suricataWorkers; i++ {
		go func() {
			for evt := range hp.suricataJobs {
				if err := hp.GeneratePCAPAndRunSuricata(evt); err != nil {
					fmt.Println("[!] Suricata job error:", err)
				}
			}
		}()
	}
	// Splunk HEC workers
	for i := 0; i < splunkWorkers; i++ {
		go func() {
			for evt := range hp.splunkJobs {
				if err := sendToSplunk(evt); err != nil {
					fmt.Println("[!] Splunk job error:", err)
				}
			}
		}()
	}
}
