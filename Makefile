SHELL=/bin/bash

CB=cert-bundler
CW=cert-watcher

usage:
	@echo Usage
	@echo
	@echo "make build             - build both apps - server and watcher"
	@echo "make build-server      - build the cert-bundler server app"
	@echo "make build-watcher     - build the client watcher app"
	@echo "make test-bundler-fail - should fail"
	@echo "make test-bundler-win  - should succeed when bundler is run on WSL and tested from a Window CMD box"
	@echo "make test-bundler-wsl  - should succeed when bundler is run on WSL and tested from another wsl shell"

fmt:
	go fmt ./...

build: fmt build-server build-watcher lsbin

build-server:
	-GOOS=linux GOARCH=amd64 go build -C cmd/$(CB) -o ../../bin/$(CB) -v .
	-GOOS=windows GOARCH=amd64 go build -C cmd/$(CB) -o ../../bin/$(CB).exe -v .

build-watcher:
	-GOOS=linux GOARCH=amd64 go build -C cmd/$(CW) -o ../../bin/$(CW) -v .

lsbin:
	-ls -lh bin
	-file bin/*
	-ldd bin/*

test-server-fail: build mkcert
	bin/$(CB) --cert example/server.crt --key example/server.key --valid-client-domain example.local

test-server-win: build mkcert
	bin/$(CB) --cert example/server.crt --key example/server.key --valid-client-domain mshome.net

test-server-wsl: build mkcert
	bin/$(CB) --cert example/server.crt --key example/server.key --valid-client-domain wsl.local

mkcert:
	mkdir -p example
	-rm example/*
	openssl req -new -x509 -days 5 -nodes -text -out example/server.crt -keyout example/server.key -subj "/CN=localhost"
