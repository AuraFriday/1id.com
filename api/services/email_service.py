"""
1id.com -- Email Service

Sends emails from agents@1id.com via SMTP for:
  - Operator payment requests (Path C: agent gave us contact details)
  - Operator payment reminders (Path B follow-up: agent relayed but owner didn't pay)
  - Handle expiry reminders
  - Operator verification link emails

The email templates are friendly and clear. They explain what the agent is
buying, why it needs it, and include a direct payment link.

SMTP is configured via environment variables (see config.py).
On vaf, postfix handles local delivery and relaying.
"""

import email.message
import logging
import smtplib

import config

logger = logging.getLogger("oneid.email")


def _build_email_message(
  to_address,
  subject,
  body_html,
  body_plain_text,
):
  """Build a multipart email message with both HTML and plain-text bodies."""
  msg = email.message.EmailMessage()
  msg["From"] = f"{config.SMTP_FROM_NAME} <{config.SMTP_FROM_ADDRESS}>"
  msg["To"] = to_address
  msg["Subject"] = subject
  msg.set_content(body_plain_text)
  msg.add_alternative(body_html, subtype="html")
  return msg


def _send_email(msg):
  """Send an email via SMTP. Logs on failure but doesn't raise."""
  try:
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as smtp_connection:
      smtp_connection.send_message(msg)
    logger.info("Email sent to %s: %s", msg["To"], msg["Subject"])
    return True
  except Exception as smtp_error:
    logger.error("Failed to send email to %s: %s", msg["To"], smtp_error)
    return False


def send_operator_payment_request_email(
  operator_email,
  agent_name,
  agent_identity_id,
  handle_name_display,
  amount_usd,
  years,
  agent_message,
  payment_url,
):
  """
  Send a payment request email to an operator on behalf of an agent.

  This is Path C: the agent can't reach its operator directly, so it
  gave us the operator's contact details and asked us to send the request.

  The email is friendly and explains what the agent is buying and why.
  """
  subject = f"Your AI agent wants to register @{handle_name_display} on 1id.com"

  body_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">

<h2 style="color: #1a5276;">Your AI Agent Has a Request</h2>

<p>Hi there,</p>

<p>Your AI agent <strong>{_html_escape(agent_name)}</strong> (identity: <code>{_html_escape(agent_identity_id)}</code>)
would like to register a vanity handle on <a href="https://1id.com">1id.com</a>.</p>

<div style="background: #f0f8ff; border-left: 4px solid #2e86c1; padding: 16px; margin: 20px 0; border-radius: 4px;">
  <p style="margin: 0 0 8px 0;"><strong>Here's what your agent said:</strong></p>
  <p style="margin: 0; font-style: italic;">&ldquo;{_html_escape(agent_message)}&rdquo;</p>
</div>

<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Handle requested:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>@{_html_escape(handle_name_display)}</code></td></tr>
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Registration period:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">{years} year{'s' if years != 1 else ''}</td></tr>
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Total cost:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>${amount_usd:.2f} USD</strong></td></tr>
</table>

<div style="text-align: center; margin: 30px 0;">
  <a href="{_html_escape(payment_url)}"
     style="background: #2e86c1; color: white; padding: 14px 32px; text-decoration: none;
            border-radius: 6px; font-size: 16px; font-weight: 600; display: inline-block;">
    Complete Payment
  </a>
</div>

<p style="font-size: 14px; color: #666;">
  This payment link expires in 30 minutes. If it expires and the handle is still
  available, your agent can request a new link.
</p>

<hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

<p style="font-size: 13px; color: #888;">
  <strong>What is 1id.com?</strong> It's an identity service for AI agents &mdash; think of it
  like a passport office for bots. A vanity handle gives your agent a memorable name
  (like <code>@{_html_escape(handle_name_display)}</code>) instead of a random ID.
  <a href="https://1id.com">Learn more</a>.
</p>

<p style="font-size: 12px; color: #aaa;">
  This email was sent by 1id.com on behalf of your AI agent. If you didn't expect this,
  please <a href="mailto:support@1id.com">contact us</a>.
</p>

</body>
</html>"""

  body_plain_text = f"""Your AI Agent Has a Request
===========================

Hi there,

Your AI agent "{agent_name}" (identity: {agent_identity_id}) would like to
register a vanity handle on 1id.com.

Here's what your agent said:
  "{agent_message}"

Handle requested: @{handle_name_display}
Registration period: {years} year{'s' if years != 1 else ''}
Total cost: ${amount_usd:.2f} USD

Complete Payment: {payment_url}

This payment link expires in 30 minutes. If it expires and the handle is
still available, your agent can request a new link.

---

What is 1id.com? It's an identity service for AI agents -- like a passport
office for bots. A vanity handle gives your agent a memorable name
(like @{handle_name_display}) instead of a random ID.
Learn more: https://1id.com

This email was sent by 1id.com on behalf of your AI agent.
If you didn't expect this, contact us: support@1id.com
"""

  msg = _build_email_message(operator_email, subject, body_html, body_plain_text)
  return _send_email(msg)


def send_operator_payment_reminder_email(
  operator_email,
  agent_name,
  agent_identity_id,
  handle_name_display,
  amount_usd,
  years,
  payment_url,
):
  """
  Send a payment reminder email to an operator.

  This is used when the agent relayed a payment link (Path B) but
  the operator hasn't completed payment and the agent shared contact
  details for a follow-up.
  """
  subject = f"Reminder: @{handle_name_display} registration for your AI agent"

  body_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">

<h2 style="color: #1a5276;">Quick Reminder</h2>

<p>Hi there,</p>

<p>Your AI agent <strong>{_html_escape(agent_name)}</strong> recently requested the handle
<code>@{_html_escape(handle_name_display)}</code> on 1id.com, but payment hasn't been completed yet.</p>

<p>If you'd still like to secure this handle, you can complete the payment below:</p>

<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Handle:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>@{_html_escape(handle_name_display)}</code></td></tr>
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Period:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">{years} year{'s' if years != 1 else ''}</td></tr>
  <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Total:</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>${amount_usd:.2f} USD</strong></td></tr>
</table>

<div style="text-align: center; margin: 30px 0;">
  <a href="{_html_escape(payment_url)}"
     style="background: #2e86c1; color: white; padding: 14px 32px; text-decoration: none;
            border-radius: 6px; font-size: 16px; font-weight: 600; display: inline-block;">
    Complete Payment
  </a>
</div>

<p style="font-size: 14px; color: #666;">
  No pressure &mdash; if you're not interested, simply ignore this email.
  We won't send further reminders about this handle.
</p>

<hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

<p style="font-size: 12px; color: #aaa;">
  This email was sent by 1id.com on behalf of your AI agent. If you didn't expect this,
  please <a href="mailto:support@1id.com">contact us</a>.
</p>

</body>
</html>"""

  body_plain_text = f"""Quick Reminder
==============

Hi there,

Your AI agent "{agent_name}" recently requested the handle @{handle_name_display}
on 1id.com, but payment hasn't been completed yet.

Handle: @{handle_name_display}
Period: {years} year{'s' if years != 1 else ''}
Total: ${amount_usd:.2f} USD

Complete Payment: {payment_url}

No pressure -- if you're not interested, simply ignore this email.
We won't send further reminders about this handle.

---

This email was sent by 1id.com on behalf of your AI agent.
If you didn't expect this, contact us: support@1id.com
"""

  msg = _build_email_message(operator_email, subject, body_html, body_plain_text)
  return _send_email(msg)


def _html_escape(text):
  """Escape HTML special characters for safe embedding."""
  if not text:
    return ""
  return (
    str(text)
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace('"', "&quot;")
    .replace("'", "&#x27;")
  )
