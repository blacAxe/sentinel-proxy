# Sentinel Go Security Proxy and Self Healer WAF

## Category
Security Engineering

A lightweight security gateway built in Go to protect web applications.
It sits between the user and the backend and filters requests before they reach the server.

This update improves logging, adds rule based detection, and introduces rate limiting.

## Category
Security Engineering

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

## New in latest update

* Live dashboard with request metrics and logs
* Real time chart showing requests per second
* Top attack tracking based on detected patterns
* Top IP tracking based on request volume
* Block rate calculation to quickly understand traffic health
* Alert system that detects abnormal behavior
* Terminal alerts for high block rate and suspicious IPs
* SQLite logging for persistent storage
* Modular structure with separated middleware, metrics, and services

## Example output

ALLOW ip equals local path slash proxy query empty

BLOCKED ip equals local rule SQLi UNION path slash proxy query id equals one union test

BLOCKED ip equals local reason RATE LIMIT

ALERT high block rate detected above threshold

ALERT suspicious IP detected with high request count

## Dashboard

The dashboard shows a live view of what the proxy is doing

* total requests
* allowed vs blocked traffic
* block rate percentage
* top attack pattern
* top IP sending requests
* live request log stream
* request timeline chart

This makes it easier to see patterns instead of just raw logs

## How to run

1 go mod tidy  
2 go run main.go  
3 open http localhost 8080  

## Notes

This project is for learning and demonstration

Rules are simple string checks and can be extended

Rate limiting is stored in memory and resets periodically

Some attacks may be handled upstream by hosting providers so custom patterns are used for testing

Alerts are based on simple thresholds and meant to simulate real monitoring systems

SQLite is used for basic persistence and can be extended to other databases

## Tech stack

* Go
* net http
* reverse proxy
* custom middleware
* SQLite

## Project structure

* middleware handles request filtering and flow
* metrics tracks traffic and analytics
* logger handles structured logging and persistence
* rules contains detection logic and config
* proxy forwards allowed requests
* db handles storage
* static contains dashboard UI