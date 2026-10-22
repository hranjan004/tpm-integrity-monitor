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

SELECTED_PCRS = (0, 2, 7, 16)
PCR_SELECTION = "sha256:" + ",".join(map(str, SELECTED_PCRS))


def canonical(input_value):
    return json.dumps(
        input_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def qualification(challenge_nonce, device_id, configuration):
    return hashlib.sha256(
        b"integrity-monitor/v1\0"
        + canonical(
            {
                "nonce": challenge_nonce,
                "device": device_id,
                "config": configuration,
            }
        )
    ).digest()


def config_digest(configuration):
    return hashlib.sha256(canonical(configuration)).hexdigest()


def public_key(public_key_pem):
    verification_key = serialization.load_pem_public_key(public_key_pem.encode())
    if (
        not isinstance(verification_key, rsa.RSAPublicKey)
        or verification_key.key_size < 2048
        or verification_key.key_size > 4096
    ):
        raise ValueError("unsupported_key")
    return verification_key


def decode(input_value):
    return base64.b64decode(input_value, validate=True)


class Reader:
    def __init__(self, quote_bytes):
        self.quote_bytes, self.offset = quote_bytes, 0

    def take(self, byte_count):
        if self.offset + byte_count > len(self.quote_bytes):
            raise ValueError("truncated_quote")
        chunk = self.quote_bytes[self.offset : self.offset + byte_count]
        self.offset += byte_count
        return chunk

    def number(self, number_format):
        return struct.unpack(number_format, self.take(struct.calcsize(number_format)))[
            0
        ]

    def sized(self):
        return self.take(self.number(">H"))


def parse_quote(quote_message):
    reader = Reader(quote_message)
    if reader.number(">I") != 0xFF544347 or reader.number(">H") != 0x8018:
        raise ValueError("not_tpm_quote")
    qualified_signer = reader.sized()
    bound_report = reader.sized()
    clock_ticks = reader.number(">Q")
    reset_count = reader.number(">I")
    restart_count = reader.number(">I")
    clock_is_safe = reader.number(">B")
    firmware_version = reader.number(">Q")
    if clock_is_safe != 1:
        raise ValueError("unsafe_clock")
    if reader.number(">I") != 1 or reader.number(">H") != 0x000B:
        raise ValueError("pcr_selection")
    if reader.number(">B") != 3:
        raise ValueError("pcr_selection")
    selection_mask = int.from_bytes(reader.take(3), "little")
    if selection_mask != sum(1 << pcr_index for pcr_index in SELECTED_PCRS):
        raise ValueError("pcr_selection")
    pcr_digest_bytes = reader.sized()
    if len(pcr_digest_bytes) != 32 or reader.offset != len(quote_message):
        raise ValueError("invalid_quote")
    return {
        "extra": bound_report,
        "pcr_digest": pcr_digest_bytes.hex(),
        "clock": clock_ticks,
        "reset": reset_count,
        "restart": restart_count,
        "firmware": firmware_version,
        "qualified_signer": qualified_signer.hex(),
    }


def verify(
    public_key_pem,
    quote_message,
    quote_signature,
    expected_report_binding,
    approved_pcr_digest,
):
    public_key(public_key_pem).verify(
        quote_signature, quote_message, padding.PKCS1v15(), hashes.SHA256()
    )
    parsed_quote = parse_quote(quote_message)
    if parsed_quote["extra"] != expected_report_binding:
        raise ValueError("nonce_or_config_binding")
    if parsed_quote["pcr_digest"] != approved_pcr_digest:
        raise ValueError("pcr_drift")
    return {
        field_name: field_value
        for field_name, field_value in parsed_quote.items()
        if field_name != "extra"
    }
