# Sentinel Go Security Proxy and Self Healer WAF

A lightweight security gateway built in Go to protect web applications.
It sits between the user and the backend and filters requests before they reach the server.

This update improves logging, adds rule based detection, and introduces rate limiting.

## Architecture

* Sentinel Proxy in Go handles incoming traffic
* Rule engine inspects requests for malicious patterns
* Rate limiter tracks request frequency per client
* Target App is a Node application running locally or on Render

Flow is simple

client request
go proxy inspects
allowed request goes to backend
malicious request is blocked

## Features

* Reverse proxy built with native Go HTTP tools
* Rule based detection for SQL injection and XSS patterns
* Rate limiting per IP to prevent abuse
* Real time request logging in terminal and dashboard
* Self healing process monitor for local apps

## What was added in this version

* Structured rule system using a rule list
* Cleaner logging with allow and block messages
* IP based tracking instead of global logging
* Basic rate limiting to simulate production behavior

## Example output

ALLOW ip equals local path slash proxy query empty

BLOCKED ip equals local rule SQLi UNION path slash proxy query id equals one union test

BLOCKED ip equals local reason RATE LIMIT

## How to run

1 go mod tidy
2 go run main.go
3 open http localhost 8080

## Notes

This project is for learning and demonstration

Rules are simple string checks and can be extended

Rate limiting is stored in memory and resets periodically

Some attacks may be handled upstream by hosting providers so custom patterns are used for testing

## Tech stack

* Go
* net http
* reverse proxy
* custom middleware

## Next steps

* persistent logging
* more advanced rule detection
* distributed rate limiting
* container deployment
