from __future__ import annotations

import re
import time
from urllib.parse import urlparse
from typing import Any
import httpx

# ponytail: 1secmail primary with GuerrillaMail fallback, zero auth required
SECMAIL_API = "https://www.1secmail.com/api/v1/"
GUERRILLA_API = "https://api.guerrillamail.com/ajax.php"
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
    """Manages disposable email address with automatic provider fallback."""

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0)
        self.provider = "1secmail"
        self.sid_token = ""
        self.email = ""
        self.login = ""
        self.domain = ""
        self._init_mailbox()

    def _init_mailbox(self) -> None:
        try:
            resp = self.client.get(f"{SECMAIL_API}?action=genRandomMailbox&count=1")
            if resp.status_code == 200:
                self.email = resp.json()[0]
                self.login, self.domain = self.email.split("@")
                self.provider = "1secmail"
                return
        except Exception:
            pass

        # Fallback to GuerrillaMail
        self.provider = "guerrillamail"
        resp = self.client.get(f"{GUERRILLA_API}?f=get_email_address")
        resp.raise_for_status()
        data = resp.json()
        self.email = data.get("email_addr", "")
        self.sid_token = data.get("sid_token", "")
        if "@" in self.email:
            self.login, self.domain = self.email.split("@")

    def check_messages(self) -> list[dict[str, Any]]:
        if self.provider == "1secmail":
            resp = self.client.get(f"{SECMAIL_API}?action=getMessages&login={self.login}&domain={self.domain}")
            return resp.json() if resp.status_code == 200 else []
        else:
            resp = self.client.get(f"{GUERRILLA_API}?f=check_email&seq=0&sid_token={self.sid_token}")
            if resp.status_code == 200:
                items = resp.json().get("list", [])
                return [{"id": m.get("mail_id"), "subject": m.get("mail_subject")} for m in items]
            return []

    def read_message(self, message_id: int) -> dict[str, Any]:
        if self.provider == "1secmail":
            resp = self.client.get(f"{SECMAIL_API}?action=readMessage&login={self.login}&domain={self.domain}&id={message_id}")
            resp.raise_for_status()
            return resp.json()
        else:
            resp = self.client.get(f"{GUERRILLA_API}?f=fetch_email&email_id={message_id}&sid_token={self.sid_token}")
            resp.raise_for_status()
            data = resp.json()
            return {"body": data.get("mail_body", "")}

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
