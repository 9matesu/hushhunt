from __future__ import annotations

import re
import time
from urllib.parse import urlparse
from typing import Any
import httpx

# ponytail: 1secmail public API, zero registration, zero API keys required
API_URL = "https://www.1secmail.com/api/v1/"
LINK_RE = re.compile(r'href=[\'"](https?://[^\'">\s]+)[\'"]', re.I)


def extract_activation_link(html_or_text: str, allowed_hosts: list[str]) -> str | None:
    """Extract first confirmation URL from email body matching allowed hosts."""
    for url in LINK_RE.findall(html_or_text):
        host = urlparse(url).hostname or ""
        for ah in allowed_hosts:
            if host == ah or host.endswith("." + ah):
                return url
    return None


class DisposableMailbox:
    """Manages a single disposable email address lifecycle."""

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0)
        self.email, self.login, self.domain = self._create_mailbox()

    def _create_mailbox(self) -> tuple[str, str, str]:
        resp = self.client.get(f"{API_URL}?action=genRandomMailbox&count=1")
        resp.raise_for_status()
        addr = resp.json()[0]
        login, domain = addr.split("@")
        return addr, login, domain

    def check_messages(self) -> list[dict[str, Any]]:
        resp = self.client.get(f"{API_URL}?action=getMessages&login={self.login}&domain={self.domain}")
        if resp.status_code == 200:
            return resp.json()
        return []

    def read_message(self, message_id: int) -> dict[str, Any]:
        resp = self.client.get(f"{API_URL}?action=readMessage&login={self.login}&domain={self.domain}&id={message_id}")
        resp.raise_for_status()
        return resp.json()

    def wait_for_link(self, allowed_hosts: list[str], timeout: int = 45, interval: int = 3) -> str | None:
        """Poll inbox until an activation link is detected or timeout expires."""
        deadline = time.time() + timeout
        seen_ids = set()
        while time.time() < deadline:
            for msg in self.check_messages():
                mid = msg.get("id")
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)
                body = self.read_message(mid).get("body", "")
                link = extract_activation_link(body, allowed_hosts)
                if link:
                    return link
            time.sleep(interval)
        return None
