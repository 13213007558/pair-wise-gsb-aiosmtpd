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

The ``LMTP`` class subclasses the :class:`~aiosmtpd.smtp.SMTP` class.
Its functional differences are that
it implements the ``LHLO`` command,
prohibits the use of ``HELO`` and ``EHLO``,
and answers the ``DATA`` command with one reply per accepted recipient.

Per-recipient DATA replies
--------------------------

As required by :rfc:`2033`, the ``LMTP`` class answers the ``DATA`` command
with one final reply *per accepted recipient*, in the order the ``RCPT TO``
commands were accepted.

A handler's ``handle_DATA()`` hook may therefore return a list (or tuple) of
status strings, one for each accepted recipient, in the same order as
``envelope.rcpt_tos``.  Each accepted recipient occupies exactly one position,
even if the same address was given multiple times; recipients rejected during
``RCPT TO`` do not occupy a position.

For backward compatibility, the hook may still return a single status string
(or nothing at all), in which case that status is used as the final reply for
*every* accepted recipient.

If the hook returns a list whose length does not match the number of accepted
recipients, contains an entry that is not a valid 2xx/4xx/5xx reply, or raises
an exception, then every accepted recipient receives the same deterministic
failure reply instead, and no partial set of replies is ever sent.
