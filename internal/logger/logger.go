package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/omar/sentinel-proxy/internal/events"
	db "github.com/omar/sentinel-proxy/internal/storage"
)

type Client struct {
	ch chan string
}

var clients = make(map[*Client]bool)
var clientsMu sync.Mutex

var LogChan chan string

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
}

var logFile *os.File

func broadcast(msg string) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	log.Println("[SSE] broadcasting:", msg)

	for client := range clients {
		select {
		case client.ch <- msg:
		default:
			close(client.ch)
			delete(clients, client)
			log.Println("[SSE] dropped slow client")
		}
	}
}

func Init() {
	f, err := os.OpenFile("data/logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	logFile = f
}

func Log(entry LogEntry) {
	entry.Timestamp = time.Now().Format(time.RFC3339)

	data, _ := json.Marshal(entry)
	logFile.Write(append(data, '\n'))

	msg := fmt.Sprintf(
		`{"ip":"%s","path":"%s","query":"%s","action":"%s","reason":"%s"}`,
		entry.IP,
		entry.Path,
		entry.Query,
		entry.Action,
		entry.Reason,
	)

	_, err := db.DB.Exec(`
        INSERT INTO logs (timestamp, ip, path, query, action, reason)
        VALUES (?, ?, ?, ?, ?, ?)`,
		entry.Timestamp,
		entry.IP,
		entry.Path,
		entry.Query,
		entry.Action,
		entry.Reason,
	)

	if err != nil {
		log.Println("DB insert error:", err)
	}

	// send to all SSE clients
	broadcast(msg)
}

func LogEvent(event events.SecurityEvent) {
	// write to file
	data, _ := json.Marshal(event)
	logFile.Write(append(data, '\n'))

	// send JSON to dashboard
	msgBytes, _ := json.Marshal(event)
	msg := string(msgBytes)

	broadcast(msg)
}
