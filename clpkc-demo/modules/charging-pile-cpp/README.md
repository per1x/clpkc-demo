# charging-pile-cpp

C++ charging pile client using OpenSSL.

## Responsibilities

- Connect to the cloud TCP server
- Answer HMAC challenge with the pre-shared key
- Request the partial private key through the cloud
- Build the CL full private key
- Run signed ECDH and derive the session key

## Build

```bash
./build.sh
```

## Run

```bash
./run.sh
```
