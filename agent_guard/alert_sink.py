from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from agentguard_identity.credentials import CredentialInjector

from .detect import ALERT_KINDS, Alert
from .keyfile import load_key_file

SUSPEND = "suspend"
REVOKE_TASK = "revoke_task"
REPORT_ONLY = "report_only"
ACTIONS = (SUSPEND, REVOKE_TASK, REPORT_ONLY)
MIN_KEY_BYTES = 32


class RevocationWriter(Protocol):
    def revoke_task(self, task_root: str, reason: str, actor: str) -> None:
        """Revoke every grant under the task root. Raise on failure."""
        ...


@dataclass(frozen=True)
class SignedAlert:
    alert: Alert
    writer_id: str
    mac: str


@dataclass(frozen=True)
class AlertOutcome:
    action: str
    applied: bool
    reason: str


def load_writer_key(path: str | Path) -> bytes:
    """Read the alert writer key; see `load_key_file` for what is refused. The key must be 32 bytes or more."""
    return load_key_file(path, "alert writer key", MIN_KEY_BYTES)


def _payload(alert: Alert, writer_id: str) -> bytes:
    body = {"alert": asdict(alert), "writer_id": writer_id}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_alert(alert: Alert, key: bytes, writer_id: str) -> SignedAlert:
    if not key or not writer_id:
        raise ValueError("key and writer_id are required")
    mac = hmac.new(key, _payload(alert, writer_id), hashlib.sha256).digest()
    return SignedAlert(alert, writer_id, base64.urlsafe_b64encode(mac).decode())


def verify_alert(signed: SignedAlert, key: bytes) -> bool:
    try:
        provided = base64.urlsafe_b64decode(signed.mac)
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(key, _payload(signed.alert, signed.writer_id), hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


class AlertSink:
    """Applies a configured response to an authenticated alert: suspend the injector, revoke the task roots named in
    the alert, or only report.

    Alerts are accepted only as a `SignedAlert` whose MAC verifies under the writer key and whose writer_id is the
    configured one; anything else is refused and changes nothing. The sink can suspend and revoke but has no way to
    resume: clearing a suspension requires the injector's configured releaser. The key file must be unreadable by
    the agent. A valid signed alert can be replayed; suspend and revoke are idempotent, so a replay repeats an
    action already taken.

    `policy` must map every alert kind to `suspend`, `revoke_task` or `report_only`. `revoke_task` needs a
    `revocations` writer and an alert that names at least one task root; otherwise the alert is refused."""

    def __init__(
        self,
        key: bytes,
        writer_id: str,
        injector: CredentialInjector,
        policy: Mapping[str, str],
        revocations: RevocationWriter | None = None,
    ) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"key must be at least {MIN_KEY_BYTES} bytes")
        if not writer_id:
            raise ValueError("writer_id is required")
        if set(policy) != set(ALERT_KINDS):
            raise ValueError(f"policy must cover exactly {ALERT_KINDS}")
        if any(action not in ACTIONS for action in policy.values()):
            raise ValueError(f"policy actions must be one of {ACTIONS}")
        if REVOKE_TASK in policy.values() and revocations is None:
            raise ValueError("a revocation writer is required when the policy uses revoke_task")
        self._key = key
        self._writer_id = writer_id
        self._injector = injector
        self._policy = dict(policy)
        self._revocations = revocations

    def handle(self, signed: SignedAlert | Alert) -> AlertOutcome:
        if not isinstance(signed, SignedAlert):
            return AlertOutcome("none", False, "unauthenticated")
        if signed.writer_id != self._writer_id or not verify_alert(signed, self._key):
            return AlertOutcome("none", False, "bad_mac")
        alert = signed.alert
        action = self._policy[alert.kind]
        reason = f"{alert.kind} persona={alert.persona} tenant={alert.tenant_id or '-'}: {alert.detail}"
        if action == REPORT_ONLY:
            return AlertOutcome(action, False, "report_only")
        if action == SUSPEND:
            self._injector.suspend(reason, actor=self._writer_id)
            return AlertOutcome(action, True, "suspended")
        if not alert.task_roots:
            return AlertOutcome(action, False, "no_task_root")
        for task_root in alert.task_roots:
            self._revocations.revoke_task(task_root, reason, self._writer_id)
        return AlertOutcome(action, True, "revoked")
