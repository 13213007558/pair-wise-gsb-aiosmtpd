# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test LMTP per-recipient DATA replies (RFC 2033)."""

import asyncio
import smtplib
import socket
import threading
from contextlib import contextmanager
from typing import Any, Generator, List, Tuple

import pytest

from aiosmtpd.lmtp import LMTP
from aiosmtpd.smtp import SMTP
from aiosmtpd.testing.helpers import ASYNCIO_CATCHUP_DELAY

from .conftest import AUTOSTOP_DELAY


MESSAGE = (
    b"From: sender@example.com\r\n"
    b"Subject: per-recipient test\r\n"
    b"\r\n"
    b"Test body.\r\n"
)


class ListStatusHandler:
    """Returns a fixed handle_DATA() result; records the envelopes seen."""

    def __init__(self, result: Any):
        self.result = result
        self.rcpt_tos_seen: List[List[str]] = []

    async def handle_DATA(self, server, session, envelope):
        self.rcpt_tos_seen.append(list(envelope.rcpt_tos))
        return self.result


@contextmanager
def socketpair_server(
        protocol_class, handler, client_class
) -> Generator[smtplib.SMTP, None, None]:
    """Run a real server protocol on one end of a socketpair.

    Yields a connected smtplib client talking to the other end.  Using a
    socketpair keeps the test entirely on local sockets.
    """
    client_sock, server_sock = socket.socketpair()
    loop = asyncio.new_event_loop()
    started = threading.Event()
    transports = []

    async def serve() -> None:
        transport, _ = await loop.create_connection(
            lambda: protocol_class(handler, loop=loop),
            sock=server_sock,
        )
        transports.append(transport)
        started.set()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(serve())
        loop.run_forever()
        loop.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert started.wait(AUTOSTOP_DELAY)
        client_sock.settimeout(AUTOSTOP_DELAY)
        client = client_class()
        client.sock = client_sock
        client.file = client_sock.makefile("rb")
        try:
            code, mesg = client.getreply()
            assert code == 220
            yield client
        finally:
            client.close()
    finally:

        async def shutdown() -> None:
            for transport in transports:
                transport.close()
            await asyncio.sleep(ASYNCIO_CATCHUP_DELAY)

        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                shutdown(), loop
            ).result(AUTOSTOP_DELAY)
            loop.call_soon_threadsafe(loop.stop)
        thread.join(AUTOSTOP_DELAY)
        server_sock.close()


@contextmanager
def lmtp_client(handler) -> Generator[smtplib.LMTP, None, None]:
    """Yield a real LMTP client, greeted with LHLO, ready to transact."""
    with socketpair_server(LMTP, handler, smtplib.LMTP) as client:
        # smtplib.LMTP uses LHLO for its greeting.
        code, mesg = client.ehlo("example.com")
        assert code == 250
        yield client


def send_message(
        client: smtplib.SMTP, mail_from: str, rcpt_tos: List[str]
) -> Tuple[List[str], dict, List[Tuple[int, bytes]]]:
    """Perform one LMTP transaction on an already-connected client.

    Returns (accepted, refused, replies): recipients accepted at RCPT
    time, recipients refused at RCPT time, and the final replies after
    DATA -- one reply per accepted recipient, in RCPT order.
    """
    code, mesg = client.mail(mail_from)
    assert code == 250
    accepted = []
    refused = {}
    for rcpt in rcpt_tos:
        code, mesg = client.rcpt(rcpt)
        if code in (250, 251):
            accepted.append(rcpt)
        else:
            refused[rcpt] = (code, mesg)
    assert accepted
    code, mesg = client.docmd("DATA")
    assert code == 354
    client.send(MESSAGE + b".\r\n")
    replies = [client.getreply() for _ in accepted]
    return accepted, refused, replies


class TestPerRecipientDataReplies:
    def test_mixed_statuses(self):
        handler = ListStatusHandler([
            "250 2.1.5 OK, delivered",
            "452 4.2.2 Mailbox full",
            "550 5.1.1 No such user",
        ])
        with lmtp_client(handler) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["ok@example.com", "full@example.com", "gone@example.com"],
            )
        assert refused == {}
        assert accepted == [
            "ok@example.com",
            "full@example.com",
            "gone@example.com",
        ]
        # The real LMTP client can map each final reply to its recipient,
        # and thus tell which addresses must be retried later (4xx) and
        # which failed permanently (5xx).
        outcomes = dict(zip(accepted, replies))
        assert outcomes["ok@example.com"] == (250, b"2.1.5 OK, delivered")
        assert outcomes["full@example.com"] == (452, b"4.2.2 Mailbox full")
        assert outcomes["gone@example.com"] == (550, b"5.1.1 No such user")
        retriable = [
            addr for addr, (code, _) in outcomes.items() if 400 <= code < 500
        ]
        assert retriable == ["full@example.com"]
        assert handler.rcpt_tos_seen == [accepted]

    def test_rejected_rcpt_occupies_no_slot(self):

        class Handler(ListStatusHandler):
            async def handle_RCPT(self, server, session, envelope,
                                  address, options):
                if address == "unknown@example.com":
                    return "550 5.1.1 User unknown"
                envelope.rcpt_tos.append(address)
                return "250 OK"

        handler = Handler(["250 2.1.5 OK", "452 4.2.2 Mailbox full"])
        with lmtp_client(handler) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["ok@example.com", "unknown@example.com",
                 "full@example.com"],
            )
        # The recipient rejected at RCPT time got its error immediately
        # and occupies no slot in the post-DATA replies.
        assert refused == {
            "unknown@example.com": (550, b"5.1.1 User unknown"),
        }
        assert accepted == ["ok@example.com", "full@example.com"]
        assert dict(zip(accepted, replies)) == {
            "ok@example.com": (250, b"2.1.5 OK"),
            "full@example.com": (452, b"4.2.2 Mailbox full"),
        }

    @pytest.mark.parametrize(
        "result",
        [
            ["250 OK"],                         # too few
            ["250 OK", "250 OK", "250 OK"],     # too many
            42,                                 # not a status at all
            ["250 OK", 42],                     # bad entry
        ],
    )
    def test_status_count_mismatch(self, result):
        handler = ListStatusHandler(result)
        with lmtp_client(handler) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
        assert replies == [
            (451, b"4.3.0 Local error in processing"),
            (451, b"4.3.0 Local error in processing"),
        ]

    def test_handler_exception_then_reuse_connection(self):

        class Handler:
            def __init__(self):
                self.calls = 0

            async def handle_DATA(self, server, session, envelope):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("boom")
                return ["250 2.1.5 Delivered"] * len(envelope.rcpt_tos)

        with lmtp_client(Handler()) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
            # Every accepted recipient gets a final error reply...
            assert replies == [
                (500, b"Error: (RuntimeError) boom"),
                (500, b"Error: (RuntimeError) boom"),
            ]
            # ...and the same connection stays usable for the next
            # message, with no state left over from the failed one.
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
            assert replies == [
                (250, b"2.1.5 Delivered"),
                (250, b"2.1.5 Delivered"),
            ]

    def test_handle_exception_hook_also_fails(self):

        class Handler:
            async def handle_DATA(self, server, session, envelope):
                raise RuntimeError("boom")

            async def handle_exception(self, error):
                raise ValueError("cannot describe")

        with lmtp_client(Handler()) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
        assert replies == [
            (500, b"Error: Cannot describe error"),
            (500, b"Error: Cannot describe error"),
        ]

    def test_consecutive_messages_do_not_leak_state(self):

        class Handler:
            def __init__(self):
                self.results = [
                    ["250 2.1.5 First A", "452 4.2.2 First B"],
                    None,  # default: 250 OK for every recipient
                ]
                self.rcpt_tos_seen: List[List[str]] = []

            async def handle_DATA(self, server, session, envelope):
                self.rcpt_tos_seen.append(list(envelope.rcpt_tos))
                return self.results.pop(0)

        handler = Handler()
        with lmtp_client(handler) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
            assert replies == [
                (250, b"2.1.5 First A"),
                (452, b"4.2.2 First B"),
            ]
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["c@example.com"],
            )
            # The second message gets its own fresh default reply, not
            # a leftover status from the first message.
            assert replies == [(250, b"OK")]
        assert handler.rcpt_tos_seen == [
            ["a@example.com", "b@example.com"],
            ["c@example.com"],
        ]

    def test_single_status_applies_to_all_recipients(self):
        handler = ListStatusHandler("250 2.0.0 OK queued as 1A2B3C")
        with lmtp_client(handler) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
        assert replies == [
            (250, b"2.0.0 OK queued as 1A2B3C"),
            (250, b"2.0.0 OK queued as 1A2B3C"),
        ]

    def test_no_data_hook_defaults_to_ok(self):

        class Handler:
            pass

        with lmtp_client(Handler()) as client:
            accepted, refused, replies = send_message(
                client,
                "sender@example.com",
                ["a@example.com", "b@example.com"],
            )
        assert replies == [(250, b"OK"), (250, b"OK")]


class TestSmtpSingleReplyContract:
    def test_sendmail_twice_same_connection(self):
        handler = ListStatusHandler("250 2.0.0 OK queued")
        with socketpair_server(SMTP, handler, smtplib.SMTP) as client:
            refused = client.sendmail(
                "sender@example.com",
                ["a@example.com", "b@example.com"],
                MESSAGE,
            )
            assert refused == {}
            refused = client.sendmail(
                "sender@example.com",
                ["c@example.com"],
                MESSAGE,
            )
            assert refused == {}
        # Exactly one reply after DATA keeps the protocol in sync; a
        # leftover reply from the first message would desynchronize the
        # second sendmail().
        assert handler.rcpt_tos_seen == [
            ["a@example.com", "b@example.com"],
            ["c@example.com"],
        ]

    def test_legacy_process_message(self):

        class LegacyHandler:
            def process_message(self, peer, mailfrom, rcpttos, data):
                return "250 2.0.0 Legacy OK"

        with socketpair_server(SMTP, LegacyHandler(), smtplib.SMTP) as client:
            with pytest.warns(DeprecationWarning, match="handle_DATA"):
                refused = client.sendmail(
                    "sender@example.com",
                    ["a@example.com"],
                    MESSAGE,
                )
        assert refused == {}
