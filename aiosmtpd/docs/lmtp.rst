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
it implements the ``LHLO`` command
(and prohibits the use of ``HELO`` and ``EHLO``),
and that after ``DATA`` it sends one final reply per accepted recipient,
as described below.

Per-recipient DATA replies
--------------------------

Unlike SMTP, LMTP has no queue to fall back on,
so :rfc:`2033` requires the server to report
the final delivery status of **each** recipient
once the message content has been received.
Therefore, after ``DATA`` is completed,
the ``LMTP`` class sends one final reply
**per accepted recipient**,
in the order the ``RCPT TO`` commands were accepted.
Recipients rejected during ``RCPT TO``
occupy no slot in these replies.

To support this, a handler's ``handle_DATA()`` hook
used with the ``LMTP`` class may return:

* ``None`` -- every accepted recipient gets a ``250 OK`` reply;

* a single status string -- sent as the final reply
  of every accepted recipient;

* a list of status strings -- one entry per accepted recipient,
  in :attr:`Envelope.rcpt_tos` order.
  The number of entries must equal ``len(envelope.rcpt_tos)``;
  if it does not, every accepted recipient receives
  ``451 4.3.0 Local error in processing``.

If the hook raises an exception,
every accepted recipient receives the status
produced by :meth:`~aiosmtpd.smtp.SMTP.handle_exception`
(``500 Error: ...`` by default),
and the connection stays usable for subsequent messages.
