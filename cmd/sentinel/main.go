package main

import "github.com/omar/sentinel-proxy/internal/proxy"

func main() {
	app := proxy.NewApp()
	app.Start()
}
