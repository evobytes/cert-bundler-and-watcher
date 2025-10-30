SHELL=/bin/bash

APP=cert-bundler

usage:
	@echo Usage
	@echo
	@echo make build
	@echo make test1 - should fail
	@echo make test2 - should succeed

fmt:
	go fmt ./...

build: fmt
	-GOOS=linux GOARCH=amd64 go build -C cmd/$(APP) -o ../../bin/$(APP) -v .
	-GOOS=windows GOARCH=amd64 go build -C cmd/$(APP) -o ../../bin/$(APP).exe -v .
	-ls -lh bin
	-file bin/*
	-ldd bin/*

test1: build mkcert
	bin/$(APP) --cert example/server.crt --key example/server.key --valid-client-domain example.local

test2: build mkcert
	bin/$(APP) --cert example/server.crt --key example/server.key --valid-client-domain mshome.net

mkcert:
	mkdir -p example
	-rm example/*
	openssl req -new -x509 -days 5 -nodes -text -out example/server.crt -keyout example/server.key -subj "/CN=localhost"
