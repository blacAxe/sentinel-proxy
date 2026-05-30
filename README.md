# Sentinel Security Proxy

![CI](https://github.com/blacAxe/sentinel-proxy/actions/workflows/ci.yml/badge.svg)

## Category

Security Engineering


Sentinel is a lightweight security proxy written in Go that sits in front of backend services and inspects incoming traffic before it reaches the application.

It started as a reverse proxy and WAF experiment, then evolved into an identity-aware security layer with request inspection, JWT validation, rate limiting, structured events, metrics, and real-time dashboard visibility.

This service is not just a reverse proxy — it is where identity becomes enforcement:

* JWTs issued by the Identity Provider are validated here
* access control decisions are made in real time
* malicious or suspicious traffic is blocked before it reaches the backend

It acts as the gatekeeper of the system.

---

## Architecture

```text
Client Request
      │
      ▼
Sentinel Proxy
      │
      ├── Request ID Middleware
      ├── JWT Identity Middleware
      ├── Rate Limiter
      ├── WAF Rule Engine
      └── Reverse Proxy
              │
              ▼
        Backend Service
```

Sentinel is built as a modular Go service with clear separation of concerns:

* **Proxy Layer** — handles all incoming traffic and forwards it to the target service
* **Middleware Chain** — request ID, rate limiting, and WAF inspection
* **Rule Engine** — pattern-based detection for SQLi, XSS, and path abuse
* **Event System** — every request generates a structured security event
* **Metrics Layer** — aggregates traffic, attacks, IP activity, and timelines
* **Dashboard (SSE)** — streams live logs and metrics to the UI
* **Target App** — any backend (local or deployed)

---

## Role in the Platform

Sentinel Proxy is responsible for enforcing all security decisions.

It receives requests that already include identity (JWTs from the IdP) and applies:

* authentication validation
* role-based access control
* WAF inspection
* rate limiting

Unlike the Identity Provider, which creates identity, this service enforces it.

This separation allows the system to scale and evolve without coupling authentication logic to request handling.

---

## Core Features

* Reverse proxy built using Go’s `net/http` and `httputil`
* Rule-based WAF detecting SQL injection, XSS, and suspicious paths
* Per-IP rate limiting to reduce abuse and scanning
* Identity-aware protection for sensitive routes using JWT validation
* Real-time dashboard with:

  * live request logs (SSE)
  * traffic metrics (allowed vs blocked)
  * attack breakdown and top IP tracking
* Structured JSON event pipeline powering both logs and metrics
* Timeout + failure handling for upstream services
* Local persistence using SQLite
* Live streaming logs via Server-Sent Events (SSE) powering the Sentinel OS dashboard

---

## Event & Processing Flow

Every request goes through a consistent pipeline:

1. Request enters proxy
2. Optional **JWT validation** for protected endpoints
3. Middleware chain applies:

   * request ID
   * rate limiting
   * WAF inspection
4. A structured `SecurityEvent` is created
5. Event is:

   * streamed to the dashboard (logs)
   * recorded into metrics (analytics)
6. Request is either:

   * forwarded to upstream
   * or blocked with a response

This keeps logging, metrics, and security decisions **fully consistent and centralized**.

---

## Real-Time Visibility

All security events are streamed live to the frontend dashboard using Server-Sent Events.

This enables:

* live request logs
* immediate visibility into attacks
* real-time feedback on allowed vs blocked traffic

The dashboard is not simulated — it reflects actual request flow through the proxy.

---

## Example Events

```json
{
  "event_type": "security",
  "ip": "::1",
  "path": "/?id=1 union select",
  "attack_detected": true,
  "attack_type": "SQLi UNION",
  "action": "blocked",
  "timestamp": 1714880000
}
```

---

## How to Run

```bash
go mod tidy
go run cmd/sentinel/main.go
```

Then open:

http://localhost:8081/dashboard/

---

## Tech Stack

* Go (net/http, reverse proxy)
* JWT (authentication / identity validation)
* SQLite (local storage)
* JSON (event pipeline + dashboard streaming)

---

## Notes

This project focuses on building security systems from first principles:

* understanding how traffic flows through a proxy
* designing a simple WAF engine
* structuring events for observability
* handling failures and timeouts
* keeping components loosely coupled

It’s intentionally built without heavy frameworks to stay close to how real systems work under the hood.

---

## What This Demonstrates

- Reverse proxy design in Go
- Middleware-based request processing
- WAF rule evaluation
- JWT-aware request validation
- Rate limiting and abuse prevention
- Structured security event generation
- Real-time observability through logs and metrics
- Backend security engineering from first principles