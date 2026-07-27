from __future__ import annotations

import pytest

from identity.egress import EgressPolicy


def test_deny_all_is_network_none():
    assert EgressPolicy.deny_all().network_args("docker") == ["--network=none"]


def test_allow_all_is_default_network():
    assert EgressPolicy.allow_all().network_args("docker") == []


def test_default_is_deny():
    assert EgressPolicy().default == "deny"
    assert EgressPolicy().network_args("docker") == ["--network=none"]


def test_host_allowlist_fails_loud():
    policy = EgressPolicy(default="deny", allow_hosts=("example.com",))
    with pytest.raises(NotImplementedError):
        policy.network_args("docker")


def test_allows_membership():
    policy = EgressPolicy(default="deny", allow_hosts=("example.com",))
    assert policy.allows("example.com")
    assert not policy.allows("evil.com")


def test_allow_all_allows_any_host():
    assert EgressPolicy.allow_all().allows("anything.com")


def test_invalid_default_rejected():
    with pytest.raises(ValueError):
        EgressPolicy(default="maybe")
