from __future__ import annotations

from typing import Any

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage


@dataclass(slots=True)
class EmailDeliveryConfig:
    mode: str = "console"
    from_address: str = "noreply@example.invalid"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool = True


def deliver_email(
    *, config: EmailDeliveryConfig, recipient: str, subject: str, text_body: str
) -> dict[str, Any]:
    """Deliver one transactional email.

    Console mode intentionally does not print the message body because it may contain
    one-time verification/reset/invitation tokens. The API exposes development tokens
    separately outside production for local workflows.
    """
    if config.mode == "console":
        return {"status": "accepted_console", "recipient": recipient, "subject": subject}
    if config.mode != "smtp":
        raise RuntimeError(f"Unsupported email delivery mode: {config.mode}")
    if not config.smtp_host:
        raise RuntimeError("SMTP host is required")

    message = EmailMessage()
    message["From"] = config.from_address
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text_body)

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=20) as client:
        if config.smtp_starttls:
            client.starttls()
        if config.smtp_username:
            client.login(config.smtp_username, config.smtp_password or "")
        refused = client.send_message(message)
        if refused:
            raise RuntimeError("SMTP server refused one or more recipients")
    return {"status": "delivered", "recipient": recipient, "subject": subject}
