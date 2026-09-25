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
and implements the ``LHLO`` command,
and prohibits the use of ``HELO`` and ``EHLO``.

Per-recipient DATA results
==========================

As required by :rfc:`2033`,
after the final ``.`` of the ``DATA`` phase
the server sends one final reply for each recipient
that was accepted with ``RCPT TO``,
in the order the ``RCPT TO`` commands were accepted.
Recipients rejected during ``RCPT TO`` do not get a reply slot.

To support this, an LMTP handler's ``handle_DATA()`` hook
may return a list of status strings,
one per accepted recipient, in that same order.
For convenience, a single status string
(or no return value at all) applies to every recipient.

If the handler raises an exception,
or returns a list whose length
does not match the number of accepted recipients,
every accepted recipient gets a ``451 4.3.0`` temporary failure
so the client knows to retry them later.
