"""Durable, TTL-limited DNS alias prefixes, scoped to the listener and DNS class."""

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

DomainChain = tuple[str, ...]
AliasKey = tuple[int, int, str]
Origins = dict[DomainChain, float]
AliasRows = dict[tuple[str, DomainChain], float]


class AliasStore:
    def __init__(self, path: Path, clock: Callable[[], float]) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with suppress(FileExistsError):
            path.touch(mode=0o600, exist_ok=False)
        self.path = path
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            # Old stores used wall time. Anchor those rows at the last database
            # write, so a clock correction during downtime cannot age them out.
            last_write = path.stat().st_mtime
            db.execute(
                """CREATE TABLE IF NOT EXISTS aliases (
                    policy INTEGER, rdclass INTEGER, target TEXT, prefix TEXT, expires REAL,
                    PRIMARY KEY (policy, rdclass, target, prefix)
                ) WITHOUT ROWID"""
            )

            db.execute("CREATE TABLE IF NOT EXISTS alias_clock (tick REAL NOT NULL)")
            checkpoint = db.execute("SELECT tick FROM alias_clock").fetchone()
            now = clock()
            if checkpoint is None:
                db.execute("UPDATE aliases SET expires = (expires - ?) + ?", (last_write, now))
                db.execute("INSERT INTO alias_clock VALUES (?)", (now,))
            elif checkpoint[0] > now:
                # Uptime reset. Preserve the TTL remaining at the last write.
                db.execute("UPDATE aliases SET expires = (expires - ?) + ?", (checkpoint[0], now))
                db.execute("UPDATE alias_clock SET tick=?", (now,))

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
            db.execute("UPDATE alias_clock SET tick=max(tick, ?)", (now,))
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
