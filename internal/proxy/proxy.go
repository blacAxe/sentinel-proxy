package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/omar/sentinel-proxy/internal/logger"
	"github.com/omar/sentinel-proxy/internal/metrics"
	"github.com/omar/sentinel-proxy/internal/middleware"
	"github.com/omar/sentinel-proxy/internal/rules"
	"github.com/omar/sentinel-proxy/internal/config"
	"github.com/omar/sentinel-proxy/internal/events"
	db "github.com/omar/sentinel-proxy/internal/storage"
)

type App struct{}

var (
	reverseProxy *httputil.ReverseProxy
	origin       *url.URL
	targetMutex  sync.Mutex
)

func logToSentinel(action string, attack string, ip string, path string) {
	e := events.SecurityEvent{
		EventType:      "security",
		IP:             ip,
		Path:           path,
		AttackDetected: action == "blocked",
		AttackType:     attack,
		Action:         action,
		Timestamp:      time.Now().Unix(),
	}

	data, _ := json.Marshal(e)

	// send to logger
	select {
	case logger.LogChan <- string(data):
	default:
	}

	// update metrics
	metrics.RecordEvent(e)
}

func NewApp() *App {
	return &App{}
}

func (a *App) Start() {

	os.MkdirAll("data", os.ModePerm)

	logChan := make(chan string, 100)
	logger.LogChan = logChan

	logger.Init()
	rules.LoadRules()
	db.Init()

	cfg := config.Load()

	origin, err := url.Parse(cfg.Target)
	if err != nil {
		log.Fatal("Invalid target URL")
	}

	reverseProxy = httputil.NewSingleHostReverseProxy(origin)

	reverseProxy.Transport = &http.Transport{
		ResponseHeaderTimeout: 5 * time.Second,
	}

	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil && err.Error() == "context canceled" {
			return
		}
		log.Printf("[PROXY ERROR] %v\n", err)

		logToSentinel("proxy_error", err.Error(), r.RemoteAddr, r.URL.Path)

		http.Error(w, "Upstream service unavailable", http.StatusBadGateway)
	}

	reverseProxy.Director = func(r *http.Request) {
		targetMutex.Lock()
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.URL.Scheme = origin.Scheme
		r.URL.Host = origin.Host
		r.Host = origin.Host
		targetMutex.Unlock()

		r.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}

	var JwtKey = []byte(cfg.JWTSecret)

	// ===== MAIN HANDLER =====
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.HasPrefix(r.URL.Path, "/dashboard") ||
			strings.HasPrefix(r.URL.Path, "/logs") ||
			strings.HasPrefix(r.URL.Path, "/stats") {
			http.DefaultServeMux.ServeHTTP(w, r)
			return
		}

		// AUTH CHECK
		if strings.HasPrefix(r.URL.Path, "/api/secret-data") {
			authHeader := r.Header.Get("Authorization")
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return JwtKey, nil
			})

			if err != nil || !token.Valid {
				logToSentinel("auth_error", "Invalid or Missing Token", r.RemoteAddr, r.URL.Path)
				http.Error(w, "Zero Trust: Valid Passkey Token Required", http.StatusUnauthorized)
				return
			}

			logToSentinel("auth_success", "Access granted", r.RemoteAddr, r.URL.Path)
		}

		chain := middleware.Chain(
			middleware.RequestID,
			middleware.RateLimiter,
			middleware.WAF,
		)

		secured := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reverseProxy.ServeHTTP(w, r)
		}))

		secured.ServeHTTP(w, r)
	})

	// ===== ROUTES =====

	http.Handle("/dashboard/",
		http.StripPrefix("/dashboard/", http.FileServer(http.Dir("./web/static"))),
	)

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		for msg := range logger.LogChan {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			w.(http.Flusher).Flush()
		}
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := metrics.GetStats()
		timeline := metrics.GetTimeline()

		topAttack, attackCount := metrics.GetTopAttack()
		topIP, ipCount := metrics.GetTopIP()

		response := map[string]interface{}{
			"total":        stats.Total,
			"allowed":      stats.Allowed,
			"blocked":      stats.Blocked,
			"top_attack":   topAttack,
			"attack_count": attackCount,
			"top_ip":       topIP,
			"ip_count":     ipCount,
			"timeline":     timeline,
		}

		json.NewEncoder(w).Encode(response)
	})

	logToSentinel("system", "Sentinel Proxy is shielding: "+cfg.Target, "", "")
	logToSentinel("system", "Local access: http://localhost:"+cfg.Port, "", "")

	srv := &http.Server{
		Addr: ":"     + cfg.Port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
