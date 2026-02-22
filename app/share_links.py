from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Literal

LinkKind = Literal["static", "dynamic"]


@dataclass(slots=True)
class LinkRecord:
    kind: LinkKind
    created_at: float
    expires_at: float
    target: str
    uri_as_base64: bool
    acl_text: str
    source_url: str | None = None
    content: str | None = None
    mime: str | None = None


class LinkStore:
    def __init__(self, *, default_ttl_sec: int = 6 * 3600, max_items: int = 2000) -> None:
        self.default_ttl_sec = default_ttl_sec
        self.max_items = max_items
        self._records: dict[str, LinkRecord] = {}
        self._lock = threading.Lock()

    def _cleanup_locked(self, now: float) -> None:
        expired = [key for key, value in self._records.items() if value.expires_at <= now]
        for key in expired:
            self._records.pop(key, None)
        if len(self._records) <= self.max_items:
            return
        # Keep most recent records when hitting memory limit.
        by_created = sorted(self._records.items(), key=lambda item: item[1].created_at, reverse=True)
        self._records = dict(by_created[: self.max_items])

    def _new_token_locked(self) -> str:
        while True:
            token = secrets.token_urlsafe(18)
            if token not in self._records:
                return token

    def create_static(
        self,
        *,
        content: str,
        mime: str,
        target: str,
        uri_as_base64: bool,
        acl_text: str = "",
        ttl_sec: int | None = None,
    ) -> tuple[str, LinkRecord]:
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        now = time.time()
        record = LinkRecord(
            kind="static",
            created_at=now,
            expires_at=now + ttl,
            target=target,
            uri_as_base64=uri_as_base64,
            acl_text=acl_text,
            content=content,
            mime=mime,
        )
        with self._lock:
            self._cleanup_locked(now)
            token = self._new_token_locked()
            self._records[token] = record
        return token, record

    def create_dynamic(
        self,
        *,
        source_url: str,
        target: str,
        uri_as_base64: bool,
        acl_text: str = "",
        ttl_sec: int | None = None,
    ) -> tuple[str, LinkRecord]:
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        now = time.time()
        record = LinkRecord(
            kind="dynamic",
            created_at=now,
            expires_at=now + ttl,
            target=target,
            uri_as_base64=uri_as_base64,
            acl_text=acl_text,
            source_url=source_url,
        )
        with self._lock:
            self._cleanup_locked(now)
            token = self._new_token_locked()
            self._records[token] = record
        return token, record

    def get(self, token: str) -> LinkRecord | None:
        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            return self._records.get(token)
