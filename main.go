package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type SuricataAlert struct {
	UID       string
	Signature string
	Category  string
	Severity  int
	SrcIP     string
	DestPort  int
	Timestamp time.Time
}

type Event struct {
	Timestamp    time.Time
	IP           string
	Port         int
	Payload      string
	Session      []string
	Duration     time.Duration
	SessionID    string
	SuricataData []SuricataAlert
	ThreatScore  int
	Suricata     *SuricataAlert
}

type Honeypot struct {
	ports          []int
	events         chan Event
	eventMutex     sync.RWMutex
	ipLog          map[string]int
	suricataAlerts chan SuricataAlert
	suricataMap    map[string][]SuricataAlert
	history        []Event
}

func NewHoneypot(ports []int) *Honeypot {
	return &Honeypot{
		ports:          ports,
		events:         make(chan Event, 100),
		ipLog:          make(map[string]int),
		suricataAlerts: make(chan SuricataAlert, 100),
		suricataMap:    make(map[string][]SuricataAlert),
		history:        []Event{},
	}
}

func (hp *Honeypot) watchSuricataAlerts(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("[!] Failed to open Suricata log file:", err)
		return
	}

	reader := bufio.NewReader(file)
	seen := make(map[string]bool)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(1 * time.Second)
				continue
			}
			fmt.Println("[!] Error reading Suricata log:", err)
			break
		}

		var entry map[string]interface{}
		if err := json.Unmarshal(line, &entry); err != nil {
			fmt.Println("[!] JSON parse error:", err)
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

		uid := fmt.Sprintf("%s:%d:%s", srcIP, destPort, signature)
		if seen[uid] {
			continue
		}
		seen[uid] = true

		t, _ := time.Parse("2006-01-02T15:04:05.999999-0700", timestampStr)

		alert := SuricataAlert{
			UID:       uid,
			Signature: signature,
			Category:  category,
			Severity:  severity,
			SrcIP:     srcIP,
			DestPort:  destPort,
			Timestamp: t,
		}

		hp.suricataAlerts <- alert
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

func (hp *Honeypot) eventsAlertsController() {
	for {
		select {
		case evt := <-hp.events:
			fmt.Printf("[LOG] %s - %s:%d > %s\n", evt.Timestamp.Format(time.RFC3339), evt.IP, evt.Port, evt.Payload)
			if len(evt.Session) > 0 {
				fmt.Printf("[SESSION from %s] Duration: %s\n", evt.IP, evt.Duration)
				for _, cmd := range evt.Session {
					fmt.Printf("\t> %s\n", cmd)
				}
			}

			alerts := hp.suricataMap[fmt.Sprintf("%s_%d", evt.IP, evt.Port)]
			for _, alert := range alerts {
				if evt.Port == 21 { // FTP
					if alert.Timestamp.After(evt.Timestamp) && alert.Timestamp.Before(evt.Timestamp.Add(evt.Duration)) {
						evt.Suricata = &alert
						break
					}
				} else { // HTTP or others
					if alert.Timestamp.After(evt.Timestamp.Add(-1*time.Second)) && alert.Timestamp.Before(evt.Timestamp.Add(3*time.Second)) {
						evt.Suricata = &alert
						break
					}
				}
			}

			hp.eventMutex.Lock()
			hp.history = append(hp.history, evt)
			hp.eventMutex.Unlock()

		case alert := <-hp.suricataAlerts:
			fmt.Printf("[SURICATA] [%s] %s:%d -> %s (%s, Severity %d)\n",
				alert.Timestamp.Format(time.RFC3339),
				alert.SrcIP,
				alert.DestPort,
				alert.Signature,
				alert.Category,
				alert.Severity,
			)

			hp.suricataMap[fmt.Sprintf("%s_%d", alert.SrcIP, alert.DestPort)] = append(hp.suricataMap[fmt.Sprintf("%s_%d", alert.SrcIP, alert.DestPort)], alert)

		}
	}
}

func (hp *Honeypot) Start() {
	for _, port := range hp.ports {
		switch port {
		case 21:
			go hp.listenFTP(port)
		case 80:
			go hp.startHTTPHoneypot(port)
		default:
			go hp.listenOnPort(port)
		}
	}
	go hp.eventsAlertsController()
	go hp.watchSuricataAlerts("/var/log/suricata/eve.json")
}

func main() {
	hp := NewHoneypot([]int{21, 22, 80})
	hp.Start()

	select {} // Block forever
}

func (hp *Honeypot) startHTTPHoneypot(port int) {
	mux := http.NewServeMux()

	wrap := func(handler func(http.ResponseWriter, *http.Request) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			info := handler(w, r)
			ip := strings.Split(r.RemoteAddr, ":")[0]
			hp.events <- Event{
				Timestamp: time.Now(),
				IP:        ip,
				Port:      port,
				Payload:   fmt.Sprintf("%s %s > %s", r.Method, r.URL.Path, info),
			}
		}
	}

	mux.HandleFunc("/login", wrap(fakeLogin))
	mux.HandleFunc("/search", wrap(sqlInjectionBait))
	mux.HandleFunc("/comment", wrap(xssBait))
	mux.HandleFunc("/admin", wrap(fakeAdmin))
	mux.HandleFunc("/upload", wrap(fakeUpload))
	mux.HandleFunc("/config", wrap(leakConfig))
	mux.HandleFunc("/robots.txt", wrap(serveRobots))
	mux.HandleFunc("/backup.zip", wrap(fakeDownload))
	mux.HandleFunc("/shell.php", wrap(fakeShell))

	addr := fmt.Sprintf(":%d", port)
	fmt.Println("[*] HTTP honeypot running on", addr)
	http.ListenAndServe(addr, mux)
}

func fakeLogin(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		fmt.Fprintln(w, "Login failed.")
		return fmt.Sprintf("Login attempt: %s / %s", username, password)
	}
	fmt.Fprintln(w, "<form method='POST'>Username: <input name='username'/><br/>Password: <input name='password' type='password'/><br/><input type='submit'/></form>")
	return "Login form served"
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

func fakeAdmin(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseForm()
		u := r.FormValue("user")
		p := r.FormValue("pass")
		fmt.Fprintln(w, "Access Denied.")
		return fmt.Sprintf("Admin login attempt: %s / %s", u, p)
	}
	fmt.Fprintln(w, "<form method='POST'>User: <input name='user'/><br/>Pass: <input name='pass' type='password'/><br/><input type='submit'/></form>")
	return "Admin login form served"
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
