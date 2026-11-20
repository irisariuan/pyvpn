"""Durable, TTL-limited DNS alias prefixes, scoped to the listener and DNS class."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DomainChain = tuple[str, ...]
AliasKey = tuple[int, int, str]
Origins = dict[DomainChain, float]
AliasRows = dict[tuple[str, DomainChain], float]


class AliasStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)
        self.path = path
        with self._connection() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS aliases (
                    policy INTEGER, rdclass INTEGER, target TEXT, prefix TEXT, expires REAL,
                    PRIMARY KEY (policy, rdclass, target, prefix)
                ) WITHOUT ROWID"""
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        # Open an existing file only. Losing the store while running must fail closed.
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True)
        try:
            with db:
                yield db
        finally:
            db.close()

    def origins(self, key: AliasKey, now: float) -> Origins:
        with self._connection() as db:
            rows = db.execute(
                "SELECT prefix, expires FROM aliases "
                "WHERE policy=? AND rdclass=? AND target=? AND expires>?",
                (*key, now),
            )
            return {tuple(json.loads(prefix)): expires for prefix, expires in rows}

    def remember(self, key: AliasKey, rows: AliasRows, now: float, limit: int) -> None:
        with self._connection() as db:
            db.execute("DELETE FROM aliases WHERE expires<=?", (now,))
            db.executemany(
                """INSERT INTO aliases VALUES (?,?,?,?,?)
                   ON CONFLICT (policy, rdclass, target, prefix)
                   DO UPDATE SET expires=max(expires, excluded.expires)""",
                (
                    (*key[:2], target, json.dumps(prefix), expires)
                    for (target, prefix), expires in rows.items()
                    if expires > now
                ),
            )
            if db.execute("SELECT count(*) FROM aliases").fetchone()[0] > limit:
                raise RuntimeError("DNS alias tracking capacity exceeded")
