from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Token:
    subject: str
    agent_id: str
    sandbox_id: str
    trust_tier: str
    scopes: tuple[str, ...]
    exp: float
    issuer: str = "agent-guard.local"

    def expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.exp

    def payload(self) -> dict:
        data = asdict(self)
        data["scopes"] = sorted(self.scopes)
        return data


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(token: Token, secret: bytes) -> str:
    if not secret:
        raise ValueError("sign requires a non-empty secret")
    body = _canonical(token.payload())
    mac = hmac.new(secret, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body).decode() + "." + base64.urlsafe_b64encode(mac).decode()


def verify(encoded: str, secret: bytes, now: float | None = None) -> Token:
    if not secret:
        raise ValueError("verify requires a non-empty secret")
    body_b64, mac_b64 = encoded.split(".", 1)
    body = base64.urlsafe_b64decode(body_b64)
    expected = hmac.new(secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, base64.urlsafe_b64decode(mac_b64)):
        raise ValueError("token signature invalid")
    payload = json.loads(body)
    token = Token(
        subject=payload["subject"],
        agent_id=payload["agent_id"],
        sandbox_id=payload["sandbox_id"],
        trust_tier=payload["trust_tier"],
        scopes=tuple(payload["scopes"]),
        exp=payload["exp"],
        issuer=payload["issuer"],
    )
    if token.expired(now):
        raise ValueError("token expired")
    return token
