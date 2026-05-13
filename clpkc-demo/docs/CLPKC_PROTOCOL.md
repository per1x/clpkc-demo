# CL-PKC Demo Protocol

## Curve And Encoding

- Curve: `secp256r1`
- Hash: `SHA-256`
- HMAC: `HmacSHA256`
- EC point encoding: SEC1 uncompressed, `04 || X(32B) || Y(32B)`
- Scalar encoding: 32-byte unsigned big-endian hex

## Simplified Certificateless Construction

This demo uses a compact CL-PKC-compatible scalar construction that is easy to align across Java and C++:

- KGC master secret: `s`
- KGC master public key: `Ppub = sG`
- User secret value: `x_i`
- User public key: `P_i = x_i G`
- `h_i = H1(ID_i || encode(P_i)) mod n`
- Partial private key: `d_i = s * h_i mod n`
- Full private key scalar: `sk_i = (x_i + d_i) mod n`
- Full public key: `PK_i = P_i + h_i * Ppub`

Because:

`PK_i = x_i G + h_i s G = (x_i + d_i) G = sk_i G`

the verifier can recompute the sender full public key from public data.

## Socket Messages

Messages are UTF-8 JSON, one object per line.

### 1. HMAC Challenge

Cloud -> Pile:

```json
{"type":"challenge","nonce":"<hex>"}
```

Pile -> Cloud:

```json
{"type":"hmac","id":"pile-001","publicKey":"<hex>","mac":"<hex>"}
```

Where `mac = HMAC(Kshared, nonceBytes)`.

Cloud -> Pile:

```json
{"type":"auth_ok","id":"cloud-001","publicKey":"<hex>"}
```

The cloud static public key is returned here so the pile can include the receiver parameter in the first signed ECDH message.

### 2. Partial Private Key Request

Pile -> Cloud:

```json
{"type":"partial_key_request","id":"pile-001","publicKey":"<hex>"}
```

Cloud -> KGC HTTPS:

```json
{"id":"pile-001","publicKey":"<hex>"}
```

KGC -> Cloud -> Pile:

```json
{"type":"partial_key_response","curve":"secp256r1","partialPrivate":"<hex>","masterPublicKey":"<hex>"}
```

The `partialPrivate` field contains the ECIES-encrypted partial private key `d_i`. The ciphertext format (hex) is:

`R(65B) || nonce(12B) || ciphertext(32B) || tag(16B)` = 250 hex chars

Where:
- `R` is the ephemeral public key point (SEC1 uncompressed)
- `nonce` is the AES-256-GCM nonce
- `ciphertext` is the encrypted `d_i` scalar
- `tag` is the AES-256-GCM authentication tag

**ECIES Encryption** (performed by KGC):
1. Generate ephemeral key pair `(r, R = rG)`
2. Compute shared point `S = r * P_i` where `P_i` is the requester's public key
3. Derive AES-256 key: `k = SHA256(x(S))` where `x(S)` is the 32-byte X coordinate of `S`
4. Encrypt `d_i` with AES-256-GCM using key `k` and a random 12-byte nonce
5. Output: `encode(R) || nonce || ciphertext || tag`

**ECIES Decryption** (performed by the recipient, e.g., Cloud or Pile):
1. Parse `R`, `nonce`, `ciphertext`, `tag` from the received hex string
2. Compute shared point `S = x_i * R` where `x_i` is the recipient's secret scalar
3. Derive AES-256 key: `k = SHA256(x(S))`
4. Decrypt with AES-256-GCM using key `k` and nonce, verify authentication tag
5. Recover plaintext `d_i`

### 3. Signed ECDH

Pile -> Cloud:

```json
{"type":"ka_request","id":"pile-001","publicKey":"<hex>","ra":"<hex>","t":"<iso8601>","sig":"<hex>"}
```

Cloud -> Pile:

```json
{"type":"ka_response","id":"cloud-001","publicKey":"<hex>","rb":"<hex>","t":"<iso8601>","sig":"<hex>"}
```

## Signature

The transcript is length-prefixed binary:

`u16(len(RA)) || RA || u16(len(IDA)) || IDA || u16(len(WB)) || WB || u16(len(T)) || T`

The demo signature is a Schnorr-style EC signature over `secp256r1`:

- random `k`
- `R = kG`
- `e = SHA256(encode(R) || transcript) mod n`
- `s = k + e * sk_A mod n`
- signature bytes: `encode(R) || s(32B)`

This implements the requested semantic form:

`Sigma_A = sign(params, RA || IDA || WB || T, SK_A)`

## Session Key Derivation

- Shared secret point: `S = r_A * R_B = r_B * R_A`
- Session key: `SHA256(x(S) || RA || RB || ID_A || ID_B || T_A || T_B)`

Only the 32-byte X coordinate of `S` is fed into the KDF.
