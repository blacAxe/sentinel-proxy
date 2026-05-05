package main

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/omar/sentinel-proxy/internal/proxy"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found")
	}

	app := proxy.NewApp()
	app.Start()
}
