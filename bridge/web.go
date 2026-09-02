package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var adminWeb embed.FS

func adminStaticHandler() http.Handler {
	sub, err := fs.Sub(adminWeb, "web")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
