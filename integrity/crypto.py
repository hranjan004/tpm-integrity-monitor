"""Strict parser for the supported TPM2 quote profile (RSA/SHA256, one bank).

TPMS_ATTEST is network byte order, without a TPM2B size prefix in tpm2_quote
message output. Reject unsupported structures rather than guessing formats.
"""
import base64
import hashlib
import json
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PCRS = (0, 2, 7, 16)
SELECTION = "sha256:" + ",".join(map(str, PCRS))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def qualification(nonce, device, config):
    return hashlib.sha256(b"integrity-monitor/v1\0" + canonical({
        "nonce": nonce, "device": device, "config": config,
    })).digest()


def config_digest(config):
    return hashlib.sha256(canonical(config)).hexdigest()


def public_key(pem):
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048 or key.key_size > 4096:
        raise ValueError("unsupported_key")
    return key


def decode(value):
    return base64.b64decode(value, validate=True)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated_quote")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def sized(self):
        return self.take(self.number(">H"))


def parse_quote(message):
    r = Reader(message)
    if r.number(">I") != 0xff544347 or r.number(">H") != 0x8018:
        raise ValueError("not_tpm_quote")
    signer = r.sized()
    extra = r.sized()
    clock = r.number(">Q")
    reset = r.number(">I")
    restart = r.number(">I")
    safe = r.number(">B")
    firmware = r.number(">Q")
    if safe != 1:
        raise ValueError("unsafe_clock")
    if r.number(">I") != 1 or r.number(">H") != 0x000b:
        raise ValueError("pcr_selection")
    if r.number(">B") != 3:
        raise ValueError("pcr_selection")
    mask = int.from_bytes(r.take(3), "little")
    if mask != sum(1 << p for p in PCRS):
        raise ValueError("pcr_selection")
    digest = r.sized()
    if len(digest) != 32 or r.pos != len(message):
        raise ValueError("invalid_quote")
    return {"extra": extra, "pcr_digest": digest.hex(), "clock": clock,
            "reset": reset, "restart": restart, "firmware": firmware,
            "qualified_signer": signer.hex()}


def verify(pem, message, signature, expected_extra, baseline):
    public_key(pem).verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    quote = parse_quote(message)
    if quote["extra"] != expected_extra:
        raise ValueError("nonce_or_config_binding")
    if quote["pcr_digest"] != baseline:
        raise ValueError("pcr_drift")
    return {k: v for k, v in quote.items() if k != "extra"}
