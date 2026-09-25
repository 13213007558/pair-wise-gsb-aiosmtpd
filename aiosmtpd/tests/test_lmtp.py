# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test the LMTP protocol."""

import re
import socket
from contextlib import contextmanager
from smtplib import SMTP as SMTPClient
from typing import Generator, List, Optional, Sequence, Tuple

import pytest

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.lmtp import LMTP
from aiosmtpd.testing.statuscodes import SMTP_STATUS_CODES as S

from .conftest import Global


class LMTPController(Controller):
    def factory(self):
        self.smtpd = LMTP(self.handler)
        return self.smtpd


@pytest.fixture(scope="module", autouse=True)
def lmtp_controller() -> Generator[LMTPController, None, None]:
    controller = LMTPController(Sink)
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    controller.stop()


def test_lhlo(client):
    code, mesg = client.docmd("LHLO example.com")
    lines = mesg.splitlines()
    assert lines == [
        bytes(socket.getfqdn(), "utf-8"),
        b"SIZE 33554432",
        b"8BITMIME",
        b"HELP",
    ]
    assert code == 250


def test_helo(client):
    # HELO and EHLO are not valid LMTP commands.
    resp = client.helo("example.com")
    assert resp == S.S500_CMD_UNRECOG(b"HELO")


def test_ehlo(client):
    # HELO and EHLO are not valid LMTP commands.
    resp = client.ehlo("example.com")
    assert resp == S.S500_CMD_UNRECOG(b"EHLO")


def test_help(client):
    # https://github.com/aio-libs/aiosmtpd/issues/113
    resp = client.docmd("HELP")
    assert resp == S.S250_SUPPCMD_LMTP


class PerRecipientHandler:
    """Handler exercising the LMTP per-recipient DATA result contract."""

    def __init__(self, statuses=None, reject: Sequence[str] = ()):
        self.statuses = statuses
        self.reject = set(reject)
        self.deliveries: List[List[str]] = []

    async def handle_RCPT(
        self, server, session, envelope, address, rcpt_options
    ):
        if address in self.reject:
            return "550 5.1.1 Mailbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.deliveries.append(list(envelope.rcpt_tos))
        if isinstance(self.statuses, BaseException):
            raise self.statuses
        return self.statuses


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("localhost", 0))
        return sock.getsockname()[1]


@contextmanager
def lmtp_server(handler) -> Generator[LMTPController, None, None]:
    controller = LMTPController(handler, hostname="localhost", port=_free_port())
    controller.start()
    try:
        yield controller
    finally:
        controller.stop()


class RealLMTPClient:
    """A real LMTP client speaking over a socket.

    Unlike smtplib's data(), it reads one final reply per accepted
    recipient after the DATA phase, as RFC 2033 requires.
    """

    def __init__(self, host: str, port: int):
        self._smtp = SMTPClient()
        self._smtp.connect(host, port)
        code, _ = self._smtp.docmd("LHLO example.com")
        assert code == 250

    def mail(self, sender: str) -> Tuple[int, bytes]:
        return self._smtp.docmd(f"MAIL FROM:<{sender}>")

    def rcpt(self, address: str) -> Tuple[int, bytes]:
        return self._smtp.docmd(f"RCPT TO:<{address}>")

    def data(
        self, message: bytes, num_replies: int
    ) -> List[Tuple[int, bytes]]:
        """Do the DATA phase and read num_replies final replies."""
        self._smtp.putcmd("DATA")
        code, _ = self._smtp.getreply()
        assert code == 354
        self._smtp.send(self._quote(message))
        return [self._smtp.getreply() for _ in range(num_replies)]

    @staticmethod
    def _quote(message: bytes) -> bytes:
        data = re.sub(rb"\r\n|\r|\n", b"\r\n", message)
        data = re.sub(rb"(?m)^\.", b"..", data)
        if not data.endswith(b"\r\n"):
            data += b"\r\n"
        return data + b".\r\n"

    def close(self) -> None:
        self._smtp.close()


MESSAGE = b"From: sender@example.com\r\n\r\nTest body\r\n"


def test_data_per_recipient_replies():
    # One recipient accepted, one over quota (tempfail), one rejected
    # permanently; a fourth recipient is rejected at RCPT time and must
    # not occupy a slot in the DATA replies.
    handler = PerRecipientHandler(
        statuses=[
            "250 2.0.0 Delivered",
            "452 4.2.2 Mailbox full",
            "550 5.1.1 User unknown",
        ],
        reject=["gone@example.com"],
    )
    with lmtp_server(handler) as controller:
        client = RealLMTPClient(controller.hostname, controller.port)
        try:
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("ok@example.com")[0] == 250
            assert client.rcpt("full@example.com")[0] == 250
            assert client.rcpt("bad@example.com")[0] == 250
            code, _ = client.rcpt("gone@example.com")
            assert code == 550
            replies = client.data(MESSAGE, num_replies=3)
        finally:
            client.close()
    codes = [code for code, _ in replies]
    assert codes == [250, 452, 550]
    # The client can tell which recipients to retry (4xx), which were
    # delivered (2xx) and which failed permanently (5xx).
    assert [code for code, _ in replies if 200 <= code < 300] == [250]
    assert [code for code, _ in replies if 400 <= code < 500] == [452]
    assert [code for code, _ in replies if 500 <= code < 600] == [550]
    # The handler saw exactly the three accepted recipients, in order.
    assert handler.deliveries == [
        ["ok@example.com", "full@example.com", "bad@example.com"]
    ]


def test_data_handler_status_count_mismatch():
    # The handler returned fewer statuses than there are recipients;
    # every recipient must get a temporary failure so nothing is lost.
    handler = PerRecipientHandler(statuses=["250 2.0.0 Delivered"])
    with lmtp_server(handler) as controller:
        client = RealLMTPClient(controller.hostname, controller.port)
        try:
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("one@example.com")[0] == 250
            assert client.rcpt("two@example.com")[0] == 250
            replies = client.data(MESSAGE, num_replies=2)
        finally:
            client.close()
    assert [code for code, _ in replies] == [451, 451]


def test_data_handler_exception():
    # An exception in the handler must produce one temporary failure
    # per recipient, not a dropped connection or a single reply.
    handler = PerRecipientHandler(statuses=RuntimeError("boom"))
    with lmtp_server(handler) as controller:
        client = RealLMTPClient(controller.hostname, controller.port)
        try:
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("one@example.com")[0] == 250
            assert client.rcpt("two@example.com")[0] == 250
            replies = client.data(MESSAGE, num_replies=2)
        finally:
            client.close()
    assert [code for code, _ in replies] == [451, 451]


def test_data_two_messages_one_connection():
    # Two messages on the same connection: the second message must get
    # its own replies, unpolluted by the first message's state.
    handler = PerRecipientHandler()
    with lmtp_server(handler) as controller:
        client = RealLMTPClient(controller.hostname, controller.port)
        try:
            # First message: two recipients, mixed results.
            handler.statuses = ["250 2.0.0 Delivered", "452 4.2.2 Mailbox full"]
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("ok@example.com")[0] == 250
            assert client.rcpt("full@example.com")[0] == 250
            replies = client.data(MESSAGE, num_replies=2)
            assert [code for code, _ in replies] == [250, 452]
            # Second message: a single recipient; exactly one reply.
            handler.statuses = ["250 2.0.0 Delivered"]
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("ok2@example.com")[0] == 250
            replies = client.data(MESSAGE, num_replies=1)
            assert [code for code, _ in replies] == [250]
        finally:
            client.close()
    assert handler.deliveries == [
        ["ok@example.com", "full@example.com"],
        ["ok2@example.com"],
    ]


@pytest.mark.parametrize(
    "statuses, expected",
    [
        # No handler result: default 250 for every recipient.
        (None, [250, 250]),
        # A single status string applies to every recipient.
        ("250 2.0.0 Queued", [250, 250]),
    ],
)
def test_data_single_status_broadcast(
    statuses: Optional[str], expected: List[int]
):
    handler = PerRecipientHandler(statuses=statuses)
    with lmtp_server(handler) as controller:
        client = RealLMTPClient(controller.hostname, controller.port)
        try:
            assert client.mail("sender@example.com")[0] == 250
            assert client.rcpt("one@example.com")[0] == 250
            assert client.rcpt("two@example.com")[0] == 250
            replies = client.data(MESSAGE, num_replies=2)
        finally:
            client.close()
    assert [code for code, _ in replies] == expected
