# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test the LMTP protocol."""

import asyncio
import socket
from contextlib import suppress
from typing import Any, Callable, Generator, List, Tuple

import pytest
from pytest_mock import MockFixture

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.lmtp import LMTP
from aiosmtpd.smtp import SMTP
from aiosmtpd.testing.statuscodes import SMTP_STATUS_CODES as S

from .conftest import Global


class LMTPController(Controller):
    def factory(self):
        self.smtpd = LMTP(self.handler)
        return self.smtpd


@pytest.fixture(scope="module")
def lmtp_controller() -> Generator[LMTPController, None, None]:
    controller = LMTPController(Sink)
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    controller.stop()


@pytest.mark.usefixtures("lmtp_controller")
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


@pytest.mark.usefixtures("lmtp_controller")
def test_helo(client):
    # HELO and EHLO are not valid LMTP commands.
    resp = client.helo("example.com")
    assert resp == S.S500_CMD_UNRECOG(b"HELO")


@pytest.mark.usefixtures("lmtp_controller")
def test_ehlo(client):
    # HELO and EHLO are not valid LMTP commands.
    resp = client.ehlo("example.com")
    assert resp == S.S500_CMD_UNRECOG(b"EHLO")


@pytest.mark.usefixtures("lmtp_controller")
def test_help(client):
    # https://github.com/aio-libs/aiosmtpd/issues/113
    resp = client.docmd("HELP")
    assert resp == S.S250_SUPPCMD_LMTP


BCRLF = b"\r\n"


class PerRecipientHandler:
    """Returns one DATA status per accepted recipient."""

    def __init__(self, statuses: List[str]):
        self.statuses = statuses
        self.envelopes: list = []

    async def handle_DATA(self, server, session, envelope):
        self.envelopes.append(envelope)
        return self.statuses


class SingleStatusHandler:
    """Legacy-style handler returning one status for the whole transaction."""

    async def handle_DATA(self, server, session, envelope):
        return "250 2.0.0 Queued for delivery"


class EchoHandler:
    """Accepts everything, one 250 reply per accepted recipient."""

    def __init__(self):
        self.envelopes: list = []

    async def handle_DATA(self, server, session, envelope):
        self.envelopes.append(envelope)
        return ["250 OK"] * len(envelope.rcpt_tos)


class RaisingHandler:
    async def handle_DATA(self, server, session, envelope):
        raise RuntimeError("boom")


class WeirdStatusHandler:
    async def handle_DATA(self, server, session, envelope):
        return 42


class PickyRcptHandler:
    """Rejects some recipients at RCPT time; accepted ones get one slot each."""

    async def handle_RCPT(self, server, session, envelope,
                          address, rcpt_options):
        if address.startswith("bad@"):
            return "550 5.1.1 Rejected"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        return ["250 2.0.0 Delivered"] * len(envelope.rcpt_tos)


@pytest.fixture
def transport_resp(mocker: MockFixture) -> Tuple[Any, list]:
    responses: list = []
    mocked = mocker.Mock()
    mocked.write = responses.append
    #
    return mocked, responses


@pytest.fixture
def get_lmtp_protocol(
    temp_event_loop: asyncio.AbstractEventLoop,
    transport_resp: Tuple[Any, list],
) -> Callable[..., SMTP]:
    transport, _ = transport_resp

    def getter(*args, **kwargs) -> SMTP:
        proto = LMTP(*args, loop=temp_event_loop, **kwargs)
        proto.connection_made(transport)
        return proto

    return getter


def run_session(
    temp_event_loop: asyncio.AbstractEventLoop,
    protocol: SMTP,
    session_lines: List[bytes],
) -> None:
    protocol.data_received(BCRLF.join(session_lines) + BCRLF)
    with suppress(asyncio.CancelledError):
        temp_event_loop.run_until_complete(protocol._handler_coroutine)


def data_replies(responses: list, count: int) -> list:
    """Return the <count> replies sent right after the 354 response."""
    idx = responses.index(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    return responses[idx + 1: idx + 1 + count]


def mail_data_lines(
    mail_from: bytes, rcpt_tos: List[bytes]
) -> List[bytes]:
    lines = [b"MAIL FROM:<" + mail_from + b">"]
    lines += [b"RCPT TO:<" + rcpt + b">" for rcpt in rcpt_tos]
    lines += [b"DATA", b"Subject: test", b"", b"test body", b"."]
    return lines


class TestLMTPDataStatuses:
    """LMTP must send one final DATA status per accepted RCPT (RFC 2033)."""

    def test_mixed_per_recipient_statuses(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        handler = PerRecipientHandler([
            "250 2.0.0 Delivered",
            "451 4.4.1 Mailbox busy, try again later",
            "550 5.1.1 No such user",
        ])
        protocol = get_lmtp_protocol(handler)
        # The same address appearing twice occupies two result slots.
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 3) == [
            b"250 2.0.0 Delivered\r\n",
            b"451 4.4.1 Mailbox busy, try again later\r\n",
            b"550 5.1.1 No such user\r\n",
        ]

    def test_single_status_applies_to_all_recipients(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        protocol = get_lmtp_protocol(SingleStatusHandler())
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com", b"dora@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 3) == [
            b"250 2.0.0 Queued for delivery\r\n",
        ] * 3

    def test_default_status_for_all_recipients(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        protocol = get_lmtp_protocol(object())
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 2) == [b"250 OK\r\n"] * 2

    def test_state_reset_between_messages(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        handler = EchoHandler()
        protocol = get_lmtp_protocol(handler)
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com", b"dora@example.com"],
            ),
            *mail_data_lines(
                b"erin@example.com",
                [b"fred@example.com", b"gina@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        # Each message got exactly one reply per accepted recipient.
        first = responses.index(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        second = responses.index(
            b"354 End data with <CR><LF>.<CR><LF>\r\n", first + 1)
        assert responses[first + 1: first + 4] == [b"250 OK\r\n"] * 3
        assert responses[second + 1: second + 3] == [b"250 OK\r\n"] * 2
        # The handler saw a fresh envelope for the second message.
        assert len(handler.envelopes) == 2
        assert handler.envelopes[0].rcpt_tos == [
            "bart@example.com", "cris@example.com", "dora@example.com",
        ]
        assert handler.envelopes[1].rcpt_tos == [
            "fred@example.com", "gina@example.com",
        ]

    def test_rejected_rcpt_occupies_no_slot(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        protocol = get_lmtp_protocol(PickyRcptHandler())
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"bad@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        # Only the two accepted recipients get a final DATA reply; the next
        # reply after those is the QUIT response.
        assert data_replies(responses, 3) == [
            b"250 2.0.0 Delivered\r\n",
            b"250 2.0.0 Delivered\r\n",
            b"221 Bye\r\n",
        ]

    def test_status_count_mismatch(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        handler = PerRecipientHandler(["250 2.0.0 Delivered"])
        protocol = get_lmtp_protocol(handler)
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        # Nothing partial is sent; every recipient gets the same safe error.
        assert data_replies(responses, 2) == [
            b"451 4.3.0 Invalid DATA statuses from handler\r\n",
        ] * 2

    def test_invalid_status_in_list(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        handler = PerRecipientHandler(["250 2.0.0 Delivered", "bogus"])
        protocol = get_lmtp_protocol(handler)
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 2) == [
            b"451 4.3.0 Invalid DATA statuses from handler\r\n",
        ] * 2

    def test_handler_exception(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        protocol = get_lmtp_protocol(RaisingHandler())
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 2) == [
            b"500 Error: (RuntimeError) boom\r\n",
        ] * 2

    def test_invalid_scalar_status(
        self, temp_event_loop, transport_resp, get_lmtp_protocol
    ):
        protocol = get_lmtp_protocol(WeirdStatusHandler())
        run_session(temp_event_loop, protocol, [
            b"LHLO example.com",
            *mail_data_lines(
                b"anne@example.com",
                [b"bart@example.com", b"cris@example.com"],
            ),
            b"QUIT",
        ])
        _, responses = transport_resp
        assert data_replies(responses, 2) == [
            b"451 4.3.0 Invalid DATA status from handler\r\n",
        ] * 2
