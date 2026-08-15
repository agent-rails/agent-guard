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
    # Confirmation claim (RFC 7800-style): a PoPKeypair public-key thumbprint (see
    # agentguard_identity/pop.py). When set, this token is holder-bound — using it requires a
    # fresh PoPProof signed by the matching private key, not just the bearer string.
    # None means a plain bearer credential, same as every token before PoP existed.
    cnf: str | None = None

    def expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.exp

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
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise TypeError("payload must be an object")
        for field in ("subject", "agent_id", "sandbox_id", "trust_tier", "issuer"):
            if not isinstance(payload.get(field), str):
                raise TypeError(f"field '{field}' must be a string")
        scopes = payload.get("scopes")
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise TypeError("field 'scopes' must be a list of strings")
        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise TypeError("field 'exp' must be a number")
        cnf = payload.get("cnf")
        if cnf is not None and not isinstance(cnf, str):
            raise TypeError("field 'cnf' must be a string or null")
        token = Token(
            subject=payload["subject"],
            agent_id=payload["agent_id"],
            sandbox_id=payload["sandbox_id"],
            trust_tier=payload["trust_tier"],
            scopes=tuple(scopes),
            exp=exp,
            issuer=payload["issuer"],
            cnf=cnf,
        )
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as err:
        raise ValueError(f"malformed token: {err}") from err
    if token.expired(now):
        raise ValueError("token expired")
    return token
