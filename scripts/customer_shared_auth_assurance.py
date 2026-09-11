#!/usr/bin/env python3
"""Fail-closed source contract for Fiducia's strict customer Shared Auth boundary."""
from __future__ import annotations

from pathlib import Path
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    require(len(sys.argv) == 2, "usage: customer_shared_auth_assurance.py <lib.rs>")
    source = Path(sys.argv[1]).read_text(encoding="utf-8")

    marker = "pub async fn authenticate_shared"
    start = source.find(marker)
    require(start >= 0, "missing Guard::authenticate_shared")
    next_method = source.find("\n    pub async fn ", start + len(marker))
    require(next_method > start, "could not isolate authenticate_shared implementation")
    method = source[start:next_method]

    require("self.exchange(token, false)" in method, "strict customer auth must exchange provider tokens through Shared Auth")
    require("self.race_authentication(token)" not in method, "strict customer auth must not use direct-provider fallback race")
    require("Decision::without_upgrade(Outcome::Degraded" in method, "Shared Auth unavailability must fail closed as degraded")
    require("Decision::without_upgrade(Outcome::Anonymous)" in method, "missing credentials must remain anonymous")
    require("Decision::without_upgrade(Outcome::Unauthenticated)" in method, "invalid credentials must remain unauthenticated")

    for needle in (
        "pub assurance_level: u8",
        "pub auth_methods: Vec<String>",
        "assurance_level: claims.aal",
        "auth_methods: claims.amr",
        "!(1..=3).contains(&identity.assurance_level)",
        "!unique_valid_identifiers(&identity.auth_methods)",
        "strict_shared_authentication_never_accepts_direct_provider_fallback",
        "strict_shared_authentication_exchanges_provider_and_preserves_assurance",
    ):
        require(needle in source, f"missing assurance contract: {needle}")

    print("customer Shared Auth assurance contract: ok")


if __name__ == "__main__":
    main()
