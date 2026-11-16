import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def public_key_text(private_key):
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")


def read_public_key(value):
    if not isinstance(value, str):
        raise ValueError("Missing peer identity key.")
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))


def sign(private_key, data):
    return base64.b64encode(private_key.sign(canonical(data))).decode("ascii")


def verify(public_key, data, signature):
    try:
        read_public_key(public_key).verify(
            base64.b64decode(signature, validate=True), canonical(data)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Invalid peer identity signature.") from exc


def check_ticket(ticket, tracker_key):
    if not isinstance(ticket, dict) or not isinstance(ticket.get("claims"), dict):
        raise ValueError("Missing tracker ticket.")
    claims = ticket["claims"]
    verify(tracker_key, claims, ticket.get("signature"))
    if (
        not isinstance(claims.get("expires"), (int, float))
        or not time.time() < claims["expires"]
    ):
        raise ValueError("Expired tracker ticket.")
    for field in (
        "id",
        "sender",
        "recipient",
        "sender_session",
        "recipient_session",
        "sender_key",
        "recipient_key",
    ):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise ValueError("Invalid tracker ticket claims.")
    read_public_key(claims["sender_key"])
    read_public_key(claims["recipient_key"])
    return claims
