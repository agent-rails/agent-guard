from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import stat
import tempfile
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from agentguard_identity.credentials import CredentialInjector

from .detect import ALERT_KINDS, Alert
from .keyfile import load_key_file
from .report import _printable

SUSPEND = "suspend"
REVOKE_TASK = "revoke_task"
REPORT_ONLY = "report_only"
ACTIONS = (SUSPEND, REVOKE_TASK, REPORT_ONLY)
MIN_KEY_BYTES = 32
MAX_FUTURE_SKEW = 5
SEEN_FILE = "seen-alerts.jsonl"
SEEN_LOCK = "seen-alerts.lock"


class RevocationWriter(Protocol):
    def revoke_task(self, task_root: str, reason: str, actor: str) -> None:
        """Revoke every grant under the task root. Raise on failure."""
        ...


@dataclass(frozen=True)
class SignedAlert:
    alert: Alert
    writer_id: str
    issued_at: int
    alert_id: str
    mac: str


@dataclass(frozen=True)
class AlertOutcome:
    action: str
    applied: bool
    reason: str


def load_writer_key(path: str | Path) -> bytes:
    """Read the alert writer key; see `load_key_file` for what is refused. The key must be 32 bytes or more."""
    return load_key_file(path, "alert writer key", MIN_KEY_BYTES)


def _payload(alert: Alert, writer_id: str, issued_at: int, alert_id: str) -> bytes:
    body = {"alert": asdict(alert), "writer_id": writer_id, "issued_at": issued_at, "alert_id": alert_id}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_alert(alert: Alert, key: bytes, writer_id: str, issued_at: int, alert_id: str | None = None) -> SignedAlert:
    """Sign an alert. `issued_at` is integer UTC epoch seconds; `alert_id` defaults to a random id and is what the
    sink uses to refuse a replay."""
    if not key or not writer_id:
        raise ValueError("key and writer_id are required")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int):
        raise ValueError("issued_at must be integer epoch seconds")
    alert_id = alert_id or uuid.uuid4().hex
    mac = hmac.new(key, _payload(alert, writer_id, issued_at, alert_id), hashlib.sha256).digest()
    return SignedAlert(alert, writer_id, issued_at, alert_id, base64.urlsafe_b64encode(mac).decode())


def verify_alert(signed: SignedAlert, key: bytes) -> bool:
    try:
        provided = base64.urlsafe_b64decode(signed.mac)
        payload = _payload(signed.alert, signed.writer_id, signed.issued_at, signed.alert_id)
    except (binascii.Error, ValueError, TypeError):
        return False
    return hmac.compare_digest(hmac.new(key, payload, hashlib.sha256).digest(), provided)


class SeenAlerts(Exception):
    pass


class _SeenStore:
    """Alert ids already applied, kept in the broker-owned state directory. Entries older than the accepted age are
    dropped on write because an alert that old is refused by the age check anyway."""

    def __init__(self, state_dir: Path, max_age: float) -> None:
        self._dir = state_dir
        self._max_age = max_age
        self._path = state_dir / SEEN_FILE
        self._lock = state_dir / SEEN_LOCK

    def _load(self) -> dict[str, int]:
        try:
            if stat.S_ISLNK(os.lstat(self._path).st_mode):
                raise SeenAlerts(f"seen-alert state is a symlink: {self._path}")
        except FileNotFoundError:
            return {}
        entries: dict[str, int] = {}
        try:
            with self._path.open(encoding="utf-8") as handle:
                for line in handle:
                    row = json.loads(line)
                    if not isinstance(row["alert_id"], str) or type(row["issued_at"]) is not int:
                        raise ValueError("bad entry")
                    entries[row["alert_id"]] = row["issued_at"]
        except (OSError, ValueError, KeyError, TypeError) as err:
            raise SeenAlerts(f"seen-alert state is unreadable: {err}") from err
        return entries

    def claim(self, alert_id: str, issued_at: int, now: float) -> bool:
        """Record the id. False when it was already recorded."""
        try:
            lock = os.open(self._lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as err:
            raise SeenAlerts(f"seen-alert lock unavailable: {err}") from err
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            horizon = now - self._max_age - MAX_FUTURE_SKEW
            kept = {key: value for key, value in self._load().items() if value >= horizon}
            if alert_id in kept:
                return False
            kept[alert_id] = issued_at
            fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=".seen-")
            try:
                body = "".join(json.dumps({"alert_id": k, "issued_at": v}) + "\n" for k, v in sorted(kept.items()))
                os.write(fd, body.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._path)
            return True
        except OSError as err:
            raise SeenAlerts(f"seen-alert state is unwritable: {err}") from err
        finally:
            os.close(lock)


class AlertSink:
    """Applies a configured response to an authenticated alert: suspend the injector, revoke the task roots named in
    the alert, or only report.

    Alerts are accepted only as a `SignedAlert` whose MAC verifies under the writer key and whose writer_id is the
    configured one; anything else is refused and changes nothing. The sink can suspend and revoke but has no way to
    resume: clearing a suspension requires the injector's configured releaser. The key file must be unreadable by
    the agent.

    A signed alert is accepted once. It carries `issued_at` and `alert_id` under the MAC; the sink refuses an alert
    older than `max_age` seconds or dated more than 5 seconds ahead of `clock`, and refuses an alert id it has
    already applied. Applied ids are persisted in `state_dir` (the injector's broker-owned directory), so a replay
    cannot re-suspend after the releaser clears a suspension. The id is recorded before the action runs: if the
    action then raises, that alert is consumed and the detector must issue a new one. An unreadable seen-state
    refuses every alert.

    `policy` must map every alert kind to `suspend`, `revoke_task` or `report_only`. `revoke_task` needs a
    `revocations` writer and an alert that names at least one task root; otherwise the alert is refused."""

    def __init__(
        self,
        key: bytes,
        writer_id: str,
        injector: CredentialInjector,
        policy: Mapping[str, str],
        revocations: RevocationWriter | None = None,
        *,
        state_dir: str | Path,
        clock: Callable[[], float],
        max_age: float,
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
        if max_age <= 0:
            raise ValueError("max_age must be positive")
        directory = Path(state_dir)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError(f"state_dir must be a real directory owned by the current user: {directory}")
        self._seen = _SeenStore(directory, max_age)
        self._clock = clock
        self._max_age = max_age
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
        now = self._clock()
        if not (now - self._max_age <= signed.issued_at <= now + MAX_FUTURE_SKEW):
            return AlertOutcome(action, False, "stale")
        try:
            first_use = self._seen.claim(signed.alert_id, signed.issued_at, now)
        except SeenAlerts:
            return AlertOutcome(action, False, "seen_state_unreadable")
        if not first_use:
            return AlertOutcome(action, False, "replayed")
        reason = _printable(f"{alert.kind} persona={alert.persona} tenant={alert.tenant_id or '-'}: {alert.detail}")
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
