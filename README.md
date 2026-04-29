# Sentinel-Go: Security Proxy & Self-Healer [Web Application Firewall (WAF)]

A lightweight security gateway built in Go to protect microservices. It acts as a "Guardian" between the user and the application.

## Architecture

* **Sentinel Proxy (Go):** Intercepts traffic to block malicious patterns (SQLi, custom blocks) before they hit the server.
* **Process Healer (Go):** Monitors the app process and automatically restarts it if it crashes.
* **Target App (Node.js):** The protected service (hosted on Render or locally).

## Features

* **Virtual Patching:** Blocks attacks at the edge (e.g., custom "banana" pattern block).
* **Self-Healing:** Uses `os/exec` to ensure 100% uptime for local services.
* **Cloud Ready:** Automated Host-header remapping for Render/Aiven compatibility.

## Getting Started

1. **Configure Target:** Set your Render URL in `main.go`.
2. **Install Dependencies:** ```powershell
   go mod tidy
