#!/usr/bin/env python3
"""JWT encoder/decoder/validator — HMAC-SHA256 (HS256).

Usage:
    python jwt_codec.py encode '{"sub":"1234","name":"Alice"}' "secret"
    python jwt_codec.py decode "eyJ..." "secret"
    python jwt_codec.py --test
"""
import base64, hashlib, hmac, json, sys, time

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def encode(payload: dict, secret: str, algorithm="HS256", exp_seconds=None) -> str:
    header = {"alg": algorithm, "typ": "JWT"}
    if exp_seconds: payload = {**payload, "iat": int(time.time()), "exp": int(time.time()) + exp_seconds}
    h = _b64url_encode(json.dumps(header, separators=(',',':')).encode())
    p = _b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    msg = f"{h}.{p}"
    if algorithm == "HS256":
        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    elif algorithm == "HS384":
        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha384).digest()
    elif algorithm == "HS512":
        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return f"{msg}.{_b64url_encode(sig)}"

def decode(token: str, secret: str = None, verify=True) -> dict:
    parts = token.split('.')
    if len(parts) != 3: raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    if verify and secret:
        alg = header.get("alg", "HS256")
        expected = encode(payload, secret, alg).split('.')[2]
        if parts[2] != expected:
            raise ValueError("Invalid signature")
        if "exp" in payload and payload["exp"] < time.time():
            raise ValueError("Token expired")
    return {"header": header, "payload": payload}

def decode_no_verify(token: str) -> dict:
    return decode(token, verify=False)

def test():
    print("=== JWT Codec Tests ===\n")
    secret = "super-secret-key"

    # Encode/decode
    payload = {"sub": "1234567890", "name": "Alice", "admin": True}
    token = encode(payload, secret)
    parts = token.split('.')
    assert len(parts) == 3
    print(f"✓ Encoded: {token[:50]}...")

    result = decode(token, secret)
    assert result["payload"]["name"] == "Alice"
    assert result["header"]["alg"] == "HS256"
    print(f"✓ Decoded: {result['payload']}")

    # Wrong secret
    try:
        decode(token, "wrong-secret")
        assert False
    except ValueError as e:
        assert "signature" in str(e).lower()
    print("✓ Wrong secret rejected")

    # No-verify decode
    result2 = decode_no_verify(token)
    assert result2["payload"]["admin"] == True
    print("✓ No-verify decode")

    # Expiry
    token_exp = encode({"data": 1}, secret, exp_seconds=-10)  # already expired
    try:
        decode(token_exp, secret)
        assert False
    except ValueError as e:
        assert "expired" in str(e).lower()
    print("✓ Expired token rejected")

    # Valid expiry
    token_ok = encode({"data": 1}, secret, exp_seconds=3600)
    decode(token_ok, secret)
    print("✓ Valid expiry accepted")

    # HS384/512
    for alg in ["HS384", "HS512"]:
        t = encode({"x": 1}, secret, algorithm=alg)
        r = decode(t, secret)
        assert r["header"]["alg"] == alg
    print("✓ HS384/HS512")

    # Base64url
    assert _b64url_decode(_b64url_encode(b'\xff\xfe\xfd')) == b'\xff\xfe\xfd'
    print("✓ Base64url roundtrip")

    print("\nAll tests passed! ✓")

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "--test": test()
    elif args[0] == "encode": print(encode(json.loads(args[1]), args[2]))
    elif args[0] == "decode": print(json.dumps(decode(args[1], args[2])["payload"], indent=2))
