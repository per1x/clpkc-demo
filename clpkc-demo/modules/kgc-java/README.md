# kgc-java

Java HTTPS KGC service for the CL-PKC demo.

## Responsibilities

- Generate system master secret and master public key
- Receive `id + publicKey`
- Return the corresponding partial private key

## Build

```bash
./build.sh
```

## Generate Dev Certificate

```bash
./gen-dev-cert.sh
```

## Run

Generate a development PKCS12 keystore first if `certs/kgc-keystore.p12` does not exist:

```bash
keytool -genkeypair \
  -alias kgc \
  -keyalg EC \
  -groupname secp256r1 \
  -storetype PKCS12 \
  -keystore certs/kgc-keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=localhost, OU=Demo, O=CLPKC, L=SZ, ST=GD, C=CN"

keytool -exportcert \
  -alias kgc \
  -rfc \
  -keystore certs/kgc-keystore.p12 \
  -storepass changeit \
  -file certs/kgc-cert.pem
```

Then:

```bash
./run.sh
```
