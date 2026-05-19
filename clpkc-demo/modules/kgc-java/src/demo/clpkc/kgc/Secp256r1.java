package demo.clpkc.kgc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Secp256r1 {
    public static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    public static final BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    public static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    public static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    public static final Point G = new Point(
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        false
    );

    public record Point(BigInteger x, BigInteger y, boolean infinity) {
    }

    private final SecureRandom random = new SecureRandom();

    public BigInteger randomScalar() {
        BigInteger r;
        do {
            r = new BigInteger(N.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(N) >= 0);
        return r;
    }

    public Point multiply(Point p, BigInteger k) {
        Point result = new Point(BigInteger.ZERO, BigInteger.ZERO, true);
        Point addend = p;
        BigInteger n = k.mod(N);
        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = add(result, addend);
            }
            addend = doublePoint(addend);
            n = n.shiftRight(1);
        }
        return result;
    }

    public Point add(Point p, Point q) {
        if (p.infinity()) {
            return q;
        }
        if (q.infinity()) {
            return p;
        }
        if (p.x().equals(q.x())) {
            if (p.y().add(q.y()).mod(P).equals(BigInteger.ZERO)) {
                return new Point(BigInteger.ZERO, BigInteger.ZERO, true);
            }
            return doublePoint(p);
        }
        BigInteger lambda = q.y().subtract(p.y()).multiply(q.x().subtract(p.x()).mod(P).modInverse(P)).mod(P);
        BigInteger rx = lambda.multiply(lambda).subtract(p.x()).subtract(q.x()).mod(P);
        BigInteger ry = lambda.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new Point(rx, ry, false);
    }

    private Point doublePoint(Point p) {
        if (p.infinity() || p.y().equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, true);
        }
        BigInteger lambda = p.x().multiply(p.x()).multiply(BigInteger.valueOf(3)).add(A)
            .multiply(p.y().multiply(BigInteger.TWO).modInverse(P)).mod(P);
        BigInteger rx = lambda.multiply(lambda).subtract(p.x().shiftLeft(1)).mod(P);
        BigInteger ry = lambda.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new Point(rx, ry, false);
    }

    public byte[] encode(Point p) {
        if (p.infinity()) {
            throw new IllegalArgumentException("cannot encode infinity");
        }
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed(p.x(), 32), 0, out, 1, 32);
        System.arraycopy(toFixed(p.y(), 32), 0, out, 33, 32);
        return out;
    }

    public Point decode(byte[] data) {
        if (data.length != 65 || data[0] != 0x04) {
            throw new IllegalArgumentException("invalid point");
        }
        byte[] xb = Arrays.copyOfRange(data, 1, 33);
        byte[] yb = Arrays.copyOfRange(data, 33, 65);
        BigInteger x = new BigInteger(1, xb);
        BigInteger y = new BigInteger(1, yb);
        if (!isOnCurve(x, y)) {
            throw new IllegalArgumentException("point not on curve");
        }
        return new Point(x, y, false);
    }

    public boolean isOnCurve(BigInteger x, BigInteger y) {
        BigInteger x3 = x.modPow(BigInteger.valueOf(3), P);
        BigInteger ax = A.multiply(x).mod(P);
        BigInteger rhs = x3.add(ax).add(B).mod(P);
        BigInteger y2 = y.multiply(y).mod(P);
        return y2.equals(rhs);
    }

    public byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[size];
        int copyStart = raw.length > size ? raw.length - size : 0;
        int copyLen = Math.min(raw.length, size);
        System.arraycopy(raw, copyStart, out, size - copyLen, copyLen);
        return out;
    }

    /**
     * Hash-to-curve via try-and-increment: H1(data) -> Point on secp256r1.
     * Uses SHA-256, appends a 4-byte counter, treats the digest as an x-coordinate
     * candidate and solves for y using the Tonelli-Shanks shortcut (P ≡ 3 mod 4).
     */
    public Point hashToCurve(byte[]... dataParts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int counter = 0; counter < 256; counter++) {
                MessageDigest mdc = (MessageDigest) md.clone();
                for (byte[] part : dataParts) {
                    mdc.update(part);
                }
                mdc.update(new byte[]{
                    (byte) (counter >> 24), (byte) (counter >> 16),
                    (byte) (counter >> 8), (byte) counter
                });
                byte[] digest = mdc.digest();

                BigInteger x = new BigInteger(1, digest).mod(P);
                if (x.signum() == 0) continue;

                // y² = x³ + ax + b  (mod P)
                BigInteger x3 = x.modPow(BigInteger.valueOf(3), P);
                BigInteger ax = A.multiply(x).mod(P);
                BigInteger rhs = x3.add(ax).add(B).mod(P);

                // For P ≡ 3 mod 4: sqrt(a) = a^((P+1)/4) mod P
                BigInteger exp = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
                BigInteger y = rhs.modPow(exp, P);

                BigInteger y2 = y.multiply(y).mod(P);
                if (!y2.equals(rhs)) continue;

                // Choose parity from last bit of digest
                boolean wantEven = (digest[digest.length - 1] & 1) == 0;
                boolean yEven = y.mod(BigInteger.TWO).signum() == 0;
                if (wantEven != yEven) {
                    y = P.subtract(y);
                }
                return new Point(x, y, false);
            }
            throw new IllegalStateException("hashToCurve: failed after 256 attempts");
        } catch (Exception e) {
            throw new IllegalStateException("hashToCurve: " + e.getMessage(), e);
        }
    }
}
