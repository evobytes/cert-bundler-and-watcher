# cert-bundler

Simple SSL cert renewal solution for private networks

## What it does:

**cert-bundler** Serves up an all-in-one ssl certificate file suitable for use in Apache/HTTPD and NGINX servers.

It automatically retrieves intermediate certificates and servers the resultant bundle over http on port 47900.

The callable URL is http://address.of.server:47900/.well-known/ssl/<certificate_name>\_bundle.pem

For example, `example_com_bundle.pem` or, if a wildcard cert, `wildcard_example_com_bundle.pem`.

**cert-watcher** Runs on client servers and acquires certs and fresh certs from the above cert-bundler service.

## Development requirements

The applications were developed on WSL Ubuntu 24 with Go 1.24

## Runtime requirements

- Linux or Windows - the Makefile creates binaries for both platforms.

- A candidate signed/issued by a root CA - e.g. GoDaddy - in two parts:
  - server.crt - contains the signed certificate
  - server.key - contains the private key

## Running the server application

```bash
$ ./cert-bundler --cert path-to-cert.crt --key path-to-private.key --valid-client-domain example.com
```

This will only accept requests from DNS-valid hosts in the example.com domain.

## Running the client application

```bash
$ ./cert-watcher --cert /etc/ssl/path_to_cert_bundle.pem --well-known host.name.or.ip.address
```

This will expect to find the cert bundle as named at the cert-bundle server running on the defined host.

## Testing - the notes below assume your running tests from within WSL

Use `make test1` which assumes openssl in installed as it creates a 5-day cert.

Then, from another terminal, call `curl -v http://your.ip:47900/.well-known/ssl/localhost_bundle.com` to demo operation.

`test1` should intentially fail as it expects a dns entry from `example.local` domain.

Use `make test2` which recreates the certs but this time uses the `.mshone.net` domain - and tests when run on Windows should work.

```

```
