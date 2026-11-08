from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

INJECTABLE_STATES = frozenset({"reserved", "issued"})
SUSPEND_FILE = "suspended.json"


class OperationLike(Protocol):
    op_id: str
    tenant_id: str
    task_id: str
    tool: str
    resource: str
    cost: int
    verdict_allowed: bool
    expires_at: float

    def digest(self) -> str: ...


class ReservationLike(Protocol):
    op_id: str
    digest: str
    state: str


class SecretStore(Protocol):
    def get(self, name: str) -> bytes:
        """Return the secret, or raise KeyError. There is no default."""
        ...


class CredentialMinter(Protocol):
    def mint(self, secret: bytes, executor_key_id: str, audience: str, request_digest: str, ttl: float) -> Any: ...


class DuplicateIssuance(Exception):
    pass


@dataclass(frozen=True)
class IssuanceRecord:
    """Ids and hashes only. Never a secret and never the minted credential."""

    issuance_id: str
    op_id: str
    tenant_id: str
    task_id: str
    tool: str
    request_digest: str
    executor_key_id: str
    audience: str
    issued_at: float
    expires_at: float


class IssuanceStore(Protocol):
    def lookup(self, op_id: str) -> IssuanceRecord | None: ...

    def append(self, record: IssuanceRecord) -> None:
        """Durably record the issuance. Raise DuplicateIssuance if the op_id is already recorded; any other
        failure to write must also raise."""
        ...


class MemoryIssuanceStore:
    def __init__(self) -> None:
        self.records: dict[str, IssuanceRecord] = {}

    def lookup(self, op_id: str) -> IssuanceRecord | None:
        return self.records.get(op_id)

    def append(self, record: IssuanceRecord) -> None:
        if record.op_id in self.records:
            raise DuplicateIssuance(record.op_id)
        self.records[record.op_id] = record


class JsonlIssuanceStore:
    """Append-only JSONL issuance log, fsynced per record. Single-writer: duplicate detection is check-then-append."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def lookup(self, op_id: str) -> IssuanceRecord | None:
        if not self._path.exists():
            return None
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                if row["op_id"] == op_id:
                    return IssuanceRecord(**row)
        return None

    def append(self, record: IssuanceRecord) -> None:
        if self.lookup(record.op_id) is not None:
            raise DuplicateIssuance(record.op_id)
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(asdict(record), sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


@dataclass(frozen=True)
class InjectedCredential:
    issuance_id: str
    credential: Any = field(repr=False)
    executor_key_id: str
    audience: str
    request_digest: str
    expires_at: float


@dataclass(frozen=True)
class Refusal:
    reason: str
    issuance_id: str | None = None


class CredentialInjector:
    """Mints a short-lived credential for one reserved operation, after an allow decision.

    The credential is bound to the executor key, the audience and the request digest. It is never bound to an
    agent key, and it is returned to the trusted executor only. The issuance record is written before minting, so
    a crash or retry can never produce a second credential for the same op_id; if minting fails after the write,
    the op_id stays consumed and an operator reconciles it.

    `secret_names` maps a tool to the name of the secret in `store`; an unmapped tool is refused.

    Suspension is persisted in `state_dir`, which must be owned by the broker and unwritable by the agent; code
    running as the same OS user can delete or roll back the state, so isolation depends on the deployment mode.
    Only the configured `releaser` can resume. Anything present at the state path, including corrupt, unreadable
    or symlinked state, counts as suspended.

    A suspension stops new injections only; credentials already issued live until their ttl.
    `inject` returns a `Refusal` for every refused case and does not raise for them."""

    def __init__(
        self,
        store: SecretStore,
        minter: CredentialMinter,
        issuance: IssuanceStore,
        secret_names: Mapping[str, str],
        executor_key_id: str,
        audience: str,
        max_ttl: float,
        clock: Callable[[], float],
        state_dir: str | Path,
        releaser: str,
    ) -> None:
        if not executor_key_id or not audience:
            raise ValueError("executor_key_id and audience are required")
        if max_ttl <= 0:
            raise ValueError("max_ttl must be positive")
        if not releaser:
            raise ValueError("releaser is required")
        self._store = store
        self._minter = minter
        self._issuance = issuance
        self._secret_names = dict(secret_names)
        self._executor_key_id = executor_key_id
        self._audience = audience
        self._max_ttl = max_ttl
        self._clock = clock
        self._releaser = releaser
        self._state_dir = Path(state_dir)
        self._state_path = self._state_dir / SUSPEND_FILE
        self._prepare_state_dir()

    def _prepare_state_dir(self) -> None:
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = os.lstat(self._state_dir).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError(f"state_dir must be a real directory, not a symlink: {self._state_dir}")

    @property
    def suspended(self) -> bool:
        try:
            os.lstat(self._state_path)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return True

    def suspend(self, reason: str, actor: str) -> None:
        """Persist a suspension. An existing suspension is kept as first written."""
        self._prepare_state_dir()
        try:
            mode = os.lstat(self._state_path).st_mode
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(mode):
                raise ValueError(f"suspend state path is a symlink: {self._state_path}")
            return
        fd, tmp = tempfile.mkstemp(dir=self._state_dir, prefix=".suspend-")
        try:
            os.write(fd, json.dumps({"suspended": True, "reason": reason, "actor": actor}).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._state_path)

    def resume(self, releaser: str) -> None:
        if releaser != self._releaser:
            raise PermissionError(f"{releaser!r} is not the configured releaser")
        try:
            os.unlink(self._state_path)
        except FileNotFoundError:
            pass

    def inject(self, operation: OperationLike, reservation: ReservationLike) -> InjectedCredential | Refusal:
        if self.suspended:
            return Refusal("suspended")
        if not operation.verdict_allowed:
            return Refusal("verdict_not_allowed")
        request_digest = operation.digest()
        if reservation.op_id != operation.op_id:
            return Refusal("op_id_mismatch")
        if reservation.digest != request_digest:
            return Refusal("digest_mismatch")
        if reservation.state not in INJECTABLE_STATES:
            return Refusal("reservation_state")
        now = self._clock()
        if now >= operation.expires_at:
            return Refusal("operation_expired")
        existing = self._issuance.lookup(operation.op_id)
        if existing is not None:
            return Refusal("already_issued", existing.issuance_id)
        secret_name = self._secret_names.get(operation.tool)
        if secret_name is None:
            return Refusal("secret_not_configured")
        try:
            secret = self._store.get(secret_name)
        except KeyError:
            return Refusal("secret_missing")
        ttl = min(self._max_ttl, operation.expires_at - now)
        record = IssuanceRecord(
            issuance_id=hashlib.sha256(f"{operation.op_id}:{request_digest}".encode()).hexdigest()[:32],
            op_id=operation.op_id,
            tenant_id=operation.tenant_id,
            task_id=operation.task_id,
            tool=operation.tool,
            request_digest=request_digest,
            executor_key_id=self._executor_key_id,
            audience=self._audience,
            issued_at=now,
            expires_at=now + ttl,
        )
        try:
            self._issuance.append(record)
        except DuplicateIssuance:
            return Refusal("already_issued", record.issuance_id)
        except Exception:
            return Refusal("issuance_unwritable")
        try:
            credential = self._minter.mint(secret, self._executor_key_id, self._audience, request_digest, ttl)
        except Exception:
            return Refusal("mint_failed", record.issuance_id)
        return InjectedCredential(
            issuance_id=record.issuance_id,
            credential=credential,
            executor_key_id=self._executor_key_id,
            audience=self._audience,
            request_digest=request_digest,
            expires_at=record.expires_at,
        )
