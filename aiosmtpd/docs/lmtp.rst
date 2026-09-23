.. _LMTP:

================
 The LMTP class
================

:rfc:`2033` defines the :boldital:`Local Mail Transport Protocol`.
In many ways, this is very similar to SMTP, but with no guarantees of queuing.
It is, in a sense, an alternative to ESMTP,
and is often used for local mail routing
(e.g. from a Mail Transport Agent to a local command or system)
where the unreliability of internet connectivity is not an issue.

The ``LMTP`` class subclasses the :class:`~aiosmtpd.smtp.SMTP` class
and its only functional difference is that
it implements the ``LHLO`` command,
and prohibits the use of ``HELO`` and ``EHLO``.

In addition, as required by :rfc:`2033`, the ``DATA`` command concludes
with one reply per accepted ``RCPT TO`` recipient, sent in the order the
recipients were accepted. The statuses come from the
:meth:`handle_DATA <aiosmtpd.handlers.Debugging.handle_DATA>` hook:

* If the hook returns a single status string (the historical contract),
  that status is reported for every accepted recipient.
* If the hook returns a list of status strings, each entry is reported
  for the corresponding recipient in ``envelope.rcpt_tos``. The list
  must match the accepted recipients exactly; recipients rejected
  during ``RCPT TO`` do not occupy a slot, while an address accepted
  twice occupies two slots.

If the hook returns a mismatched or invalid list, or raises an
exception, every recipient receives the same deterministic error reply
(``451`` or ``500`` respectively) and no partial set of replies is
ever sent.
