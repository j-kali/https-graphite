# https-graphite
HTTPS proxy for graphite with mTLS authentication

## Usage

```
Usage of ./https-graphite:
  -CA string
        CA used for signing clients
  -CAkey string
        Key for CA used for signing clients
  -cacert value
        CA certificate file (can be defined multiple times)
  -cert string
        Server TLS certificate to use (default "certs/server.crt")
  -hostname string
        Read key and cerificate from an acme style json file and look for this host (default "localhost")
  -key string
        Server TLS key to use (default "certs/server.key")
  -port uint
        Port to listen on (default 8081)
  -target-host string
        Host to forward to (default "localhost")
  -version
        Print version and exit
```

When using `-hostname` the `-key` will be ignored and and things are fetched from the `JSON` file to which `-cert` should be pointing.

## HTTP API

### Request certificate

This `API` doesn't use `mTLS` so you can just create a key, `CSR` and ask the server to sign it.

Send your `CSR` to `/csr` using `POST` under `<port - 1>`, for example:

```
-> cat certs/client.csr | base64 | curl -k -X POST -d '@-' https://localhost:8080/csr
Received a certificate signing request: 8dea30bc-f440-4ae0-9bcb-053c8dc246d6
```

if the main app is running under port `8081`.
In response you will get an `UUID` for your request.

### Download new certificate

To get your brand new certificate you can ask `/<uuid>` the same place where you've previously sent your `CSR`, so for example:

```
curl -k https://localhost:8080/8dea30bc-f440-4ae0-9bcb-053c8dc246d6
```

If your `CSR` has been signed on the backend, you will get the certificate in response.

Use this only if you do not have the certificate yet to talk to the main `API`.

### Download and auto-renew certificate

If you already have the certificate, you can ask for it using again `/<uuid` but on the main port (behind `mTLS`).
Here, you will also get the certificate in reponse, but if it is about to expire it will get renewed first.

```
curl -k --cert $(pwd)/../../projects/https-graphite/certs/client.crt --key $(pwd)/../../projects/https-graphite/certs/client.key https://localhost:8081/8dea30bc-f440-4ae0-9bcb-053c8dc246d6
```

### Sign the certificate

To sign call `/sign/<uuid>` `API`. It uses `mTLS` so you need already a certificate to talk with it, also it should always be behind the firewall.

```
-> curl -k --cert $(pwd)/../../projects/https-graphite/certs/client.crt --key $(pwd)/../../projects/https-graphite/certs/client.key https://localhost:8079/sign/8dea30bc-f440-4ae0-9bcb-053c8dc246d6
Signed request with uuid: 8dea30bc-f440-4ae0-9bcb-053c8dc246d6
```
