from __future__ import annotations

import re
import secrets
import time
from urllib.parse import urlparse
from typing import Any
import httpx

# ponytail: 1secmail primary, GuerrillaMail then mail.tm fallback, zero auth.
# Arlo prod SSO blocks every guerrillamail domain; mail.tm domains rotate clean.
SECMAIL_API = "https://www.1secmail.com/api/v1/"
GUERRILLA_API = "https://api.guerrillamail.com/ajax.php"
MAILTM_API = "https://api.mail.tm"
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
        self.token = ""          # mailtm bearer
        self.password = ""       # mailtm account pw
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
        try:
            resp = self.client.get(f"{GUERRILLA_API}?f=get_email_address")
            resp.raise_for_status()
            data = resp.json()
            self.email = data.get("email_addr", "")
            self.sid_token = data.get("sid_token", "")
            if "@" in self.email and self.sid_token:
                self.login, self.domain = self.email.split("@")
                return
        except Exception:
            pass

        # Last resort: mail.tm (JWT-based, random-but-clean domains)
        self.provider = "mailtm"
        try:
            dom = self.client.get(f"{MAILTM_API}/domains").json()["hydra:member"][0]["domain"]
            login = secrets.token_hex(6)
            self.email = f"hush.{login}@{dom}"
            self.password = secrets.token_hex(8) + "!aA1"
            self.client.post(f"{MAILTM_API}/accounts",
                             json={"address": self.email, "password": self.password})
            self.token = self.client.post(f"{MAILTM_API}/token",
                                          json={"address": self.email,
                                                "password": self.password}).json()["token"]
        except Exception as e:
            raise RuntimeError("no disposable mailbox provider available") from e

    def check_messages(self) -> list[dict[str, Any]]:
        if self.provider == "1secmail":
            resp = self.client.get(f"{SECMAIL_API}?action=getMessages&login={self.login}&domain={self.domain}")
            return resp.json() if resp.status_code == 200 else []
        elif self.provider == "mailtm":
            resp = self.client.get(f"{MAILTM_API}/messages",
                                   headers={"Authorization": f"Bearer {self.token}"})
            if resp.status_code != 200:
                return []
            return [{"id": m["id"], "subject": m.get("subject", "")}
                    for m in resp.json().get("hydra:member", [])]
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
        elif self.provider == "mailtm":
            resp = self.client.get(f"{MAILTM_API}/messages/{message_id}",
                                   headers={"Authorization": f"Bearer {self.token}"})
            resp.raise_for_status()
            j = resp.json()
            html = j.get("html", "")
            body = j.get("text", "") + " " + (" ".join(html) if isinstance(html, list) else html)
            return {"body": body}
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
