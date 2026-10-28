package main

import (
	"net/http"

	"zhiyu.local/zhiyu-go/internal/transport/httpapi"
)

func optionalStaticWeb(api http.Handler, directory string) (http.Handler, func(), error) {
	if directory == "" {
		return api, func() {}, nil
	}
	web, err := httpapi.NewStaticWeb(api, directory)
	if err != nil {
		return nil, nil, err
	}
	return web, func() { _ = web.Close() }, nil
}
