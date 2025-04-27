package main

import (
	"bufio"
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
	ports      []int
	EventMap   map[string]*Event
	eventMutex sync.RWMutex
	history    []*Event
}

func NewHoneypot(ports []int) *Honeypot {
	return &Honeypot{
		ports:    ports,
		EventMap: make(map[string]*Event),
		history:  []*Event{},
	}
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
	file, err := os.Open(evePath)
	if err != nil {
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("[!] Error reading eve.json:", err)
			break
		}

		var entry map[string]interface{}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		/*
			if entry["event_type"] != "alert" {
				continue
			}
		*/

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

		hp.eventMutex.Lock()
		hp.EventMap[evtID].SuricataData = append(hp.EventMap[evtID].SuricataData, &alert)
		hp.eventMutex.Unlock()
	}
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

	hp.GeneratePCAPAndRunSuricata(event)
}

func (hp *Honeypot) listenFTPS(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
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
	hp := NewHoneypot([]int{443, 22, 990})
	hp.Start()

	select {} // Block forever
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

	addr := fmt.Sprintf(":%d", port)

	certFile := "cert.pem"
	keyFile := "key.pem"
	err := http.ListenAndServeTLS(addr, certFile, keyFile, mux)
	if err != nil {
		fmt.Printf("[!] HTTPS server error: %v\n", err)
	}
	fmt.Println("[*] HTTP honeypot running on", addr)
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

func (hp *Honeypot) GeneratePCAPAndRunSuricata(evt Event) error {
	filename := fmt.Sprintf("%s.pcap", evt.ID)
	pcapPath := filepath.Join("/tmp/pcaps", filename)

	err := WritePCAP(evt, pcapPath)
	if err != nil {
		return fmt.Errorf("error writing fake pcap: %v", err)
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

func WritePCAP(evt Event, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// Prepare addressing
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
