# cloud-platform-java

Java cloud platform for the CL-PKC demo.

## Responsibilities

- Connect to KGC through HTTPS
- Authenticate the charging pile by HMAC on a raw TCP socket
- Forward partial private key requests
- Verify the pile signed ECDH payload
- Return its own signed ECDH payload

## Build

```bash
./build.sh
```

## Run

The cloud trusts the KGC PEM certificate at `../kgc-java/certs/kgc-cert.pem`.

```bash
./run.sh
```
