package events

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func SendEvent(event SecurityEvent) {
	jsonData, _ := json.Marshal(event)

	resp, err := http.Post(
		"http://localhost:9001/events",
		"application/json",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return
	}
	defer resp.Body.Close()
}
