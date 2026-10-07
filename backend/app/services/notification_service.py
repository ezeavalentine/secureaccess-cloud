import smtplib
import ssl
import logging
from email.message import EmailMessage
from datetime import datetime, timedelta
from app.config import settings
from app.models import Notification, User


def deliver_pending(db):
    if not settings.SMTP_HOST: return
    now = datetime.utcnow()
    items = db.query(Notification).filter(Notification.email_sent == False,
        (Notification.email_next_attempt == None) | (Notification.email_next_attempt <= now)).order_by(Notification.created_at).limit(20).all()
    for item in items:
        user = db.get(User, item.user_id)
        if not user or not user.is_active:
            item.email_sent = True
            continue
        message = EmailMessage()
        message["Subject"], message["From"], message["To"] = "SecureAccess access update", settings.SMTP_FROM, user.email
        # Email carries no credentials, secrets, justifications, or ticket text.
        message.set_content("An access request needs your attention. Sign in to SecureAccess Cloud:\n" + settings.PUBLIC_URL)
        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                if settings.SMTP_USERNAME: smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                smtp.send_message(message)
            item.email_sent = True
        except Exception:
            logging.getLogger(__name__).exception("Notification email delivery failed; retrying")
        item.email_attempts += 1
        item.email_next_attempt = now + timedelta(seconds=min(3600, 30 * 2 ** min(item.email_attempts, 7)))
    db.commit()
