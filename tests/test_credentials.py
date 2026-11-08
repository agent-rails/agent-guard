from __future__ import annotations

import json
from dataclasses import dataclass, replace

import pytest

from agentguard_identity.credentials import (
    CredentialInjector,
    DuplicateIssuance,
    InjectedCredential,
    IssuanceRecord,
    JsonlIssuanceStore,
    MemoryIssuanceStore,
    Refusal,
)

SECRET = b"super-secret-value"
NOW = 1_000.0


@dataclass(frozen=True)
class FakeOperation:
    op_id: str = "op-1"
    tenant_id: str = "tenant-1"
    task_id: str = "task-1"
    tool: str = "deploy"
    resource: str = "svc/api"
    cost: int = 1
    verdict_allowed: bool = True
    expires_at: float = NOW + 60

    def digest(self) -> str:
        return f"digest:{self.op_id}:{self.tool}:{self.resource}:{self.cost}"


@dataclass(frozen=True)
class FakeReservation:
    op_id: str
    digest: str
    state: str = "reserved"


def _reservation(operation: FakeOperation, **overrides) -> FakeReservation:
    return FakeReservation(**{"op_id": operation.op_id, "digest": operation.digest(), **overrides})


class FakeStore:
    def __init__(self, secrets: dict[str, bytes]) -> None:
        self._secrets = secrets

    def get(self, name: str) -> bytes:
        return self._secrets[name]


class RecordingMinter:
    def __init__(self, store: MemoryIssuanceStore | None = None) -> None:
        self.calls: list[tuple] = []
        self.written_before_mint: list[bool] = []
        self._store = store

    def mint(self, secret, executor_key_id, audience, request_digest, ttl):
        if self._store is not None:
            self.written_before_mint.append(bool(self._store.records))
        self.calls.append((secret, executor_key_id, audience, request_digest, ttl))
        return {"token": "minted-token-xyz", "key": executor_key_id, "aud": audience, "req": request_digest}


class FailingMinter:
    def mint(self, secret, executor_key_id, audience, request_digest, ttl):
        raise RuntimeError("backend down")


class UnwritableStore(MemoryIssuanceStore):
    def append(self, record):
        raise OSError("read-only")


def _injector(minter=None, issuance=None, secrets=None, now=NOW, **overrides) -> CredentialInjector:
    issuance = issuance if issuance is not None else MemoryIssuanceStore()
    kwargs = {
        "store": FakeStore({"deploy-key": SECRET} if secrets is None else secrets),
        "minter": minter or RecordingMinter(issuance if isinstance(issuance, MemoryIssuanceStore) else None),
        "issuance": issuance,
        "secret_names": {"deploy": "deploy-key"},
        "executor_key_id": "executor-key-1",
        "audience": "deploy-api",
        "max_ttl": 30,
        "clock": lambda: now,
    }
    kwargs.update(overrides)
    return CredentialInjector(**kwargs)


def test_inject_mints_credential_bound_to_executor_key_audience_and_request():
    operation = FakeOperation()
    minter = RecordingMinter()
    result = _injector(minter=minter).inject(operation, _reservation(operation))
    assert isinstance(result, InjectedCredential)
    assert minter.calls == [(SECRET, "executor-key-1", "deploy-api", operation.digest(), 30)]
    assert result.executor_key_id == "executor-key-1"
    assert result.audience == "deploy-api"
    assert result.request_digest == operation.digest()
    assert result.credential["req"] == operation.digest()
    assert result.expires_at == NOW + 30


def test_ttl_is_clamped_to_operation_expiry():
    operation = FakeOperation(expires_at=NOW + 5)
    minter = RecordingMinter()
    result = _injector(minter=minter).inject(operation, _reservation(operation))
    assert isinstance(result, InjectedCredential)
    assert minter.calls[0][4] == 5
    assert result.expires_at == NOW + 5


def test_issued_reservation_state_is_accepted():
    operation = FakeOperation()
    result = _injector().inject(operation, _reservation(operation, state="issued"))
    assert isinstance(result, InjectedCredential)


def test_refuses_when_suspended():
    operation = FakeOperation()
    minter = RecordingMinter()
    injector = _injector(minter=minter)
    injector.suspend("incident", "oncall")
    assert injector.inject(operation, _reservation(operation)) == Refusal("suspended")
    assert minter.calls == []


def test_refuses_non_allow_verdict():
    operation = FakeOperation(verdict_allowed=False)
    minter = RecordingMinter()
    assert _injector(minter=minter).inject(operation, _reservation(operation)) == Refusal("verdict_not_allowed")
    assert minter.calls == []


def test_refuses_when_operation_differs_from_reservation():
    operation = FakeOperation()
    changed = replace(operation, resource="svc/other")
    minter = RecordingMinter()
    result = _injector(minter=minter).inject(changed, _reservation(operation))
    assert result == Refusal("digest_mismatch")
    assert minter.calls == []


def test_refuses_op_id_mismatch():
    operation = FakeOperation()
    result = _injector().inject(operation, _reservation(operation, op_id="op-2"))
    assert result == Refusal("op_id_mismatch")


@pytest.mark.parametrize("state", ["done", "outcome_unknown", "released", "", "RESERVED"])
def test_refuses_reservation_not_reserved_or_issued(state):
    operation = FakeOperation()
    assert _injector().inject(operation, _reservation(operation, state=state)) == Refusal("reservation_state")


@pytest.mark.parametrize("now", [NOW + 60, NOW + 61])
def test_refuses_expired_operation(now):
    operation = FakeOperation()
    minter = RecordingMinter()
    assert _injector(minter=minter, now=now).inject(operation, _reservation(operation)) == Refusal("operation_expired")
    assert minter.calls == []


def test_refuses_missing_secret_without_default():
    operation = FakeOperation()
    minter = RecordingMinter()
    result = _injector(minter=minter, secrets={}).inject(operation, _reservation(operation))
    assert result == Refusal("secret_missing")
    assert minter.calls == []


def test_refuses_tool_with_no_secret_configured():
    operation = FakeOperation(tool="unmapped")
    assert _injector().inject(operation, _reservation(operation)) == Refusal("secret_not_configured")


def test_issuance_is_written_before_minting():
    operation = FakeOperation()
    issuance = MemoryIssuanceStore()
    minter = RecordingMinter(issuance)
    _injector(minter=minter, issuance=issuance).inject(operation, _reservation(operation))
    assert minter.written_before_mint == [True]


def test_issuance_record_holds_ids_and_hashes_never_secrets():
    operation = FakeOperation()
    issuance = MemoryIssuanceStore()
    result = _injector(issuance=issuance).inject(operation, _reservation(operation))
    record = issuance.lookup("op-1")
    assert record is not None
    assert record.issuance_id == result.issuance_id
    assert record.request_digest == operation.digest()
    assert record.executor_key_id == "executor-key-1"
    serialized = json.dumps(record.__dict__)
    assert SECRET.decode() not in serialized
    assert "minted-token-xyz" not in serialized
    assert SECRET.decode() not in repr(result)
    assert "minted-token-xyz" not in repr(result)


def test_unwritable_issuance_store_refuses_and_never_mints():
    operation = FakeOperation()
    minter = RecordingMinter()
    result = _injector(minter=minter, issuance=UnwritableStore()).inject(operation, _reservation(operation))
    assert result == Refusal("issuance_unwritable")
    assert minter.calls == []


def test_retry_of_issued_op_id_never_mints_again():
    operation = FakeOperation()
    minter = RecordingMinter()
    injector = _injector(minter=minter)
    first = injector.inject(operation, _reservation(operation))
    retry = injector.inject(operation, _reservation(operation, state="issued"))
    assert isinstance(first, InjectedCredential)
    assert retry == Refusal("already_issued", first.issuance_id)
    assert len(minter.calls) == 1


def test_retry_from_new_injector_over_same_store_never_mints_again():
    operation = FakeOperation()
    issuance = MemoryIssuanceStore()
    minter = RecordingMinter()
    first = _injector(minter=minter, issuance=issuance).inject(operation, _reservation(operation))
    retry = _injector(minter=minter, issuance=issuance).inject(operation, _reservation(operation))
    assert retry == Refusal("already_issued", first.issuance_id)
    assert len(minter.calls) == 1


def test_duplicate_append_race_is_refused_not_minted():
    operation = FakeOperation()

    class RacingStore(MemoryIssuanceStore):
        def lookup(self, op_id):
            return None

    issuance = RacingStore()
    injector = _injector(issuance=issuance)
    assert isinstance(injector.inject(operation, _reservation(operation)), InjectedCredential)
    minter = RecordingMinter()
    again = _injector(minter=minter, issuance=issuance).inject(operation, _reservation(operation))
    assert isinstance(again, Refusal) and again.reason == "already_issued"
    assert minter.calls == []


def test_mint_failure_keeps_op_id_consumed():
    operation = FakeOperation()
    issuance = MemoryIssuanceStore()
    result = _injector(minter=FailingMinter(), issuance=issuance).inject(operation, _reservation(operation))
    assert isinstance(result, Refusal) and result.reason == "mint_failed"
    assert issuance.lookup("op-1") is not None
    minter = RecordingMinter()
    retry = _injector(minter=minter, issuance=issuance).inject(operation, _reservation(operation))
    assert isinstance(retry, Refusal) and retry.reason == "already_issued"
    assert minter.calls == []


def test_clock_is_injected():
    operation = FakeOperation()
    times = iter([NOW, NOW + 20])
    injector = _injector(clock=lambda: next(times))
    first = injector.inject(operation, _reservation(operation))
    assert first.expires_at == NOW + 30
    second_op = FakeOperation(op_id="op-2")
    second = injector.inject(second_op, _reservation(second_op))
    assert second.expires_at == NOW + 20 + 30


def test_constructor_rejects_bad_config():
    with pytest.raises(ValueError):
        _injector(max_ttl=0)
    with pytest.raises(ValueError):
        _injector(audience="")
    with pytest.raises(ValueError):
        _injector(executor_key_id="")


def test_jsonl_store_persists_and_rejects_duplicates(tmp_path):
    path = tmp_path / "issuance.jsonl"
    record = IssuanceRecord("i1", "op-1", "t", "task", "deploy", "d", "k", "aud", 1.0, 2.0)
    store = JsonlIssuanceStore(path)
    assert store.lookup("op-1") is None
    store.append(record)
    assert JsonlIssuanceStore(path).lookup("op-1") == record
    with pytest.raises(DuplicateIssuance):
        store.append(record)
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_jsonl_store_unwritable_path_refuses_injection(tmp_path):
    operation = FakeOperation()
    minter = RecordingMinter()
    injector = _injector(minter=minter, issuance=JsonlIssuanceStore(tmp_path / "missing-dir" / "issuance.jsonl"))
    assert injector.inject(operation, _reservation(operation)) == Refusal("issuance_unwritable")
    assert minter.calls == []
