# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test the LMTP protocol."""

import socket
from contextlib import contextmanager, suppress
from smtplib import SMTP as SMTPClient
from typing import Generator, List, Tuple

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


# region #### RFC 2033 per-recipient DATA replies ####################################


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def lmtp_factory() -> Generator:
    controllers = []

    def start(handler) -> LMTPController:
        controller = LMTPController(
            handler, hostname="127.0.0.1", port=free_port())
        controller.start()
        controllers.append(controller)
        return controller

    yield start

    for controller in controllers:
        with suppress(AssertionError):
            controller.stop()


@contextmanager
def lmtp_client(controller) -> Generator[SMTPClient, None, None]:
    with SMTPClient(controller.hostname, controller.port, timeout=5) as client:
        code, _ = client.docmd("LHLO", "example.com")
        assert code == 250
        yield client


def deliver(
    client: SMTPClient, mail_from: str, rcpt_tos: List[str]
) -> List[Tuple[int, bytes]]:
    """Deliver one message, returning the DATA replies in arrival order."""
    code, _ = client.docmd("MAIL", "FROM:<{}>".format(mail_from))
    assert code == 250
    accepted = 0
    for rcpt in rcpt_tos:
        code, _ = client.docmd("RCPT", "TO:<{}>".format(rcpt))
        if code == 250:
            accepted += 1
    code, _ = client.docmd("DATA")
    assert code == 354
    client.send(b"Subject: test\r\n\r\nsome body\r\n.\r\n")
    return [client.getreply() for _ in range(accepted)]


class PerRecipientHandler:
    """Hands a preset result back from handle_DATA."""

    def __init__(self, result):
        self.result = result
        self.envelopes = []

    async def handle_DATA(self, server, session, envelope):
        self.envelopes.append(envelope)
        return self.result


class RejectingHandler(PerRecipientHandler):
    """Rejects recipients whose local part is 'bad' during RCPT."""

    async def handle_RCPT(
        self, server, session, envelope, address, rcpt_options
    ):
        if address.startswith("bad@"):
            return "550 5.1.1 User unknown"
        envelope.rcpt_tos.append(address)
        return "250 OK"


class ExplodingHandler:
    async def handle_DATA(self, server, session, envelope):
        raise ValueError("delivery exploded")


def test_data_one_reply_per_recipient(lmtp_factory):
    handler = PerRecipientHandler([
        "250 2.1.5 Delivered",
        "451 4.2.2 Mailbox full, try again later",
        "550 5.7.1 Delivery rejected",
    ])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com",
            ["ok@example.com", "full@example.com", "no@example.com"])
    assert replies == [
        (250, b"2.1.5 Delivered"),
        (451, b"4.2.2 Mailbox full, try again later"),
        (550, b"5.7.1 Delivery rejected"),
    ]


def test_data_replies_then_next_message_starts_fresh(lmtp_factory):
    handler = PerRecipientHandler(["250 2.1.5 Fine", "550 5.1.1 Nope"])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        first = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
        assert [code for code, _ in first] == [250, 550]
        # The next message on the same connection must restart with a clean
        # envelope and a clean set of DATA replies.
        second = deliver(
            client, "bob@example.com", ["c@example.com", "d@example.com"])
        assert [code for code, _ in second] == [250, 550]
    assert len(handler.envelopes) == 2
    assert handler.envelopes[0].mail_from == "alice@example.com"
    assert handler.envelopes[0].rcpt_tos == ["a@example.com", "b@example.com"]
    assert handler.envelopes[1].mail_from == "bob@example.com"
    assert handler.envelopes[1].rcpt_tos == ["c@example.com", "d@example.com"]


def test_data_duplicate_recipients_each_occupy_a_position(lmtp_factory):
    handler = PerRecipientHandler([
        "250 2.1.5 First", "250 2.1.5 Second", "550 5.1.1 Third"])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com",
            ["dup@example.com", "dup@example.com", "other@example.com"])
    assert [code for code, _ in replies] == [250, 250, 550]
    assert handler.envelopes[0].rcpt_tos == [
        "dup@example.com", "dup@example.com", "other@example.com"]


def test_data_rejected_rcpt_occupies_no_position(lmtp_factory):
    handler = RejectingHandler(["250 2.1.5 First", "451 4.2.2 Second"])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com",
            ["good1@example.com", "bad@example.com", "good2@example.com"])
    assert [code for code, _ in replies] == [250, 451]
    assert handler.envelopes[0].rcpt_tos == [
        "good1@example.com", "good2@example.com"]


def test_data_single_status_applies_to_all_recipients(lmtp_factory):
    handler = PerRecipientHandler("250 2.0.0 Queued")
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
    assert replies == [(250, b"2.0.0 Queued"), (250, b"2.0.0 Queued")]


def test_data_status_count_mismatch_fails_all_recipients(lmtp_factory):
    handler = PerRecipientHandler(["250 2.1.5 One", "250 2.1.5 Two"])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com",
            ["a@example.com", "b@example.com", "c@example.com"])
        assert [code for code, _ in replies] == [451, 451, 451]
        # The session must survive, and a later message whose status count
        # matches its recipients is delivered normally.
        again = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
        assert [code for code, _ in again] == [250, 250]


def test_data_invalid_status_fails_all_recipients(lmtp_factory):
    handler = PerRecipientHandler(["250 2.1.5 Fine", "999 Not a reply"])
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
    assert [code for code, _ in replies] == [451, 451]


def test_data_non_status_result_fails_all_recipients(lmtp_factory):
    handler = PerRecipientHandler(None)
    controller = lmtp_factory(handler)
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
    assert [code for code, _ in replies] == [451, 451]


def test_data_handler_exception_replies_per_recipient(lmtp_factory):
    controller = lmtp_factory(ExplodingHandler())
    with lmtp_client(controller) as client:
        replies = deliver(
            client, "alice@example.com", ["a@example.com", "b@example.com"])
        assert [code for code, _ in replies] == [500, 500]
        assert b"ValueError" in replies[0][1]
        # The session must survive the handler exception.
        again = deliver(client, "alice@example.com", ["a@example.com"])
        assert [code for code, _ in again] == [500]


def test_smtp_data_still_returns_single_status(get_controller):
    # The SMTP protocol must not grow per-recipient DATA replies.
    controller = get_controller(
        Sink(), hostname="127.0.0.1", port=free_port())
    controller.start()
    try:
        with SMTPClient(
            controller.hostname, controller.port, timeout=5
        ) as client:
            client.ehlo("example.com")
            client.sendmail(
                "alice@example.com", ["a@example.com", "b@example.com"],
                "Subject: test\r\n\r\nsome body")
            # If DATA had produced more than one reply, the replies would be
            # out of sync and NOOP would not see a clean 250.
            code, _ = client.docmd("NOOP")
            assert code == 250
    finally:
        controller.stop()

# endregion
