# CL-PKC Demo Protocol

## Curve And Encoding

- Curve: `secp256r1`
- Hash: `SHA-256`
- HMAC: `HmacSHA256`
- EC point encoding: SEC1 uncompressed, `04 || X(32B) || Y(32B)`
- Scalar encoding: 32-byte unsigned big-endian hex

## Certificateless Construction (Point-Based)

This demo implements a bounded certificateless scheme where the partial private key is an elliptic curve point protected by ECDLP:

- KGC master secret: `s`
- KGC master public key: `Ppub = sG`
- User secret value: `x_i`
- User public key: `P_i = x_i G`

### Hash-to-Curve (H1)

`Q_i = H1(ID_i || P_i)` — maps (identity || public key) to a point on secp256r1 via try-and-increment:

1. Compute `digest = SHA256(ID_i || P_i || counter)` where counter starts at 0
2. Treat first 32 bytes of digest as x-coordinate: `x = digest mod p`
3. Solve `y² = x³ + ax + b (mod p)` using `y = rhs^((p+1)/4) mod p` (valid since secp256r1 p ≡ 3 mod 4)
4. If `y² ≠ rhs`, increment counter and retry
5. Choose the y whose LSB matches the LSB of the last digest byte

### Partial Private Key Generation (KGC)

`D_i = s · Q_i` — a **point** on the curve, ECDLP protects `s` from recovery.

Contrast with the broken scalar construction: `d_i = s · h_i mod n` leaks `s` via `s = d_i · h_i⁻¹ mod n`.

### Full Key Derivation (User Side)

After receiving and ECIES-decrypting `D_i`:

1. `d_i = H2(D_i) = SHA256(x(D_i) || y(D_i)) mod n` — scalar
2. Full private key: `sk_i = (x_i + d_i) mod n`
3. Derived public key: `Y_i = d_i · G`
4. Full public key: `PK_i = P_i + Y_i`

The key pair consistency holds:

`PK_i = P_i + d_i·G = (x_i + d_i)·G = sk_i·G`

### Signature Scheme (Schnorr)

- Sign: `(R = k·G, s = k + e·sk_i mod n)` where `e = SHA256(R || transcript)`
- Verify: `s·G == R + e·PK_i`

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
{"type":"auth_ok","id":"cloud-001","publicKey":"<hex>","derivedPublic":"<hex>"}
```

The cloud returns both its static public key `P_i` and its derived public key `Y_i` so the pile can compute the cloud's full public key `PK_i = P_i + Y_i`.

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

The `partialPrivate` field contains the ECIES-encrypted partial private key **point** `D_i` (65-byte SEC1 point → 65-byte plaintext). The ciphertext format (hex) is:

`R(65B) || nonce(12B) || ciphertext(65B) || tag(16B)` = 316 hex chars

Where:
- `R` is the ephemeral public key point (SEC1 uncompressed)
- `nonce` is the AES-256-GCM nonce
- `ciphertext` is the encrypted `D_i` point
- `tag` is the AES-256-GCM authentication tag

**ECIES Encryption** (performed by KGC):
1. Generate ephemeral key pair `(r, R = rG)`
2. Compute shared point `S = r · P_i` where `P_i` is the requester's public key
3. Derive AES-256 key: `k = SHA256(x(S))` where `x(S)` is the 32-byte X coordinate of `S`
4. Encrypt `D_i` (65-byte SEC1 point) with AES-256-GCM using key `k` and a random 12-byte nonce
5. Output: `encode(R) || nonce || ciphertext || tag`

**ECIES Decryption** (performed by the recipient):
1. Parse `R`, `nonce`, `ciphertext`, `tag` from the blob
2. Compute shared point `S = x_i · R`
3. Derive AES-256 key: `k = SHA256(x(S))`
4. Decrypt `ciphertext` with AES-256-GCM to recover `D_i` (65-byte SEC1 point)

### 3. Signed ECDH Key Agreement

Pile -> Cloud:

```json
{"type":"ka_request","id":"pile-001","publicKey":"<hex>","derivedPublic":"<hex>","ra":"<hex>","t":"<ts>","sig":"<hex>"}
```

The pile includes its `derivedPublic` (Y_i) so the Cloud can compute the pile's full public key `PK_i = P_i + Y_i` for signature verification.

Cloud -> Pile:

```json
{"type":"ka_response","id":"cloud-001","publicKey":"<hex>","derivedPublic":"<hex>","rb":"<hex>","t":"<ts>","sig":"<hex>"}
```

The cloud similarly includes its `derivedPublic` for the pile's verification.

### 4. Session Key

Both parties compute:

```text
SK = SHA256(x(ECDH) || RA || RB || ID_A || ID_B || T_A || T_B)
```

Where `ECDH = x_eph · peer_point`.

## Security Properties

1. **Master secret protection**: `D_i = s·Q_i` is a point on the curve. Recovering `s` from `D_i` and `Q_i` requires solving ECDLP.
2. **Key replacement resistance**: `Q_i = H1(ID_i || P_i)` binds the public key to the identity.
3. **KGC impersonation resistance**: Even the KGC (who knows `s`) cannot sign for a user without the user's secret `x_i`, because `sk_i = x_i + H2(s·Q_i)` and the KGC cannot compute `x_i`.
