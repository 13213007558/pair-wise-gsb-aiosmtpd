# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test RFC 3030 CHUNKING/BINARYMIME (BDAT) support."""

import socket
from contextlib import suppress
from typing import Generator, List

import pytest

from aiosmtpd.controller import Controller
from aiosmtpd.testing.helpers import ReceivingHandler, catchup_delay

from .conftest import Global

BCRLF = b"\r\n"


class RawClient:
    """
    A minimal raw-socket (E)SMTP client giving byte-exact control over what
    goes on the wire, which smtplib cannot do for BDAT.
    """

    def __init__(self) -> None:
        self.sock = socket.create_connection(Global.SrvAddr)
        self.reader = self.sock.makefile("rb")
        self.greeting = self.reply()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def send_slowly(self, data: bytes, step: int = 1) -> None:
        """Send data byte-by-byte (or in small odd-sized fragments)."""
        for i in range(0, len(data), step):
            self.send(data[i:i + step])

    def command(self, data: bytes) -> bytes:
        self.send(data + BCRLF)
        return self.reply()

    def bdat(self, chunk: bytes, last: bool = False) -> bytes:
        """Send a BDAT command + chunk body, then read the reply."""
        cmd = b"BDAT %d" % len(chunk)
        if last:
            cmd += b" LAST"
        self.send(cmd + BCRLF + chunk)
        return self.reply()

    def reply(self) -> bytes:
        return self.reader.readline()

    def ehlo(self) -> List[bytes]:
        self.send(b"EHLO example.org" + BCRLF)
        lines = []
        while True:
            line = self.reply()
            lines.append(line)
            if line.startswith(b"250 "):
                break
        return lines

    def mail_rcpt(self, mail: bytes = b"MAIL FROM:<anne@example.org>",
                  rcpt: bytes = b"RCPT TO:<bart@example.org>") -> None:
        assert self.command(mail).startswith(b"250")
        assert self.command(rcpt).startswith(b"250")

    def close(self) -> None:
        with suppress(OSError):
            self.reader.close()
        with suppress(OSError):
            self.sock.close()

    def __enter__(self) -> "RawClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()


@pytest.fixture
def handler() -> ReceivingHandler:
    return ReceivingHandler()


@pytest.fixture
def chunking_controller(
    get_controller, handler: ReceivingHandler
) -> Generator[Controller, None, None]:
    controller = get_controller(handler, enable_CHUNKING=True)
    controller.start()
    Global.set_addr_from(controller)
    yield controller
    with suppress(AssertionError):
        controller.stop()


def make_controller(get_controller, handler, **kwargs) -> Controller:
    controller = get_controller(handler, **kwargs)
    controller.start()
    Global.set_addr_from(controller)
    return controller


class TestChunkingExtension:
    def test_ehlo_offers_chunking(self, chunking_controller):
        with RawClient() as client:
            lines = client.ehlo()
        assert b"250-CHUNKING" in [line.strip() for line in lines]

    def test_ehlo_no_chunking_when_disabled(self, plain_controller):
        with RawClient() as client:
            lines = client.ehlo()
        assert b"250-CHUNKING" not in [line.strip() for line in lines]

    def test_help_lists_bdat_when_enabled(self, chunking_controller):
        with RawClient() as client:
            client.ehlo()
            assert b"BDAT" in client.command(b"HELP")

    def test_help_hides_bdat_when_disabled(self, plain_controller):
        with RawClient() as client:
            client.ehlo()
            assert b"BDAT" not in client.command(b"HELP")

    def test_bdat_rejected_when_disabled(self, plain_controller):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.command(b"BDAT 5 LAST").startswith(b"502")

    def test_bdat_needs_helo(self, chunking_controller):
        with RawClient() as client:
            assert client.command(b"BDAT 5 LAST").startswith(b"503")

    def test_bdat_needs_rcpt(self, chunking_controller):
        with RawClient() as client:
            client.ehlo()
            assert client.command(b"BDAT 5 LAST").startswith(b"503")

    @pytest.mark.parametrize("command", [
        b"BDAT",
        b"BDAT ",
        b"BDAT abc",
        b"BDAT -1",
        b"BDAT 1.5",
        b"BDAT 1 EXTRA",
        b"BDAT 1 LAST EXTRA",
    ])
    def test_bdat_bad_syntax(self, chunking_controller, command):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.command(command).startswith(b"501")

    def test_mail_body_binarymime_accepted(self, chunking_controller):
        with RawClient() as client:
            client.ehlo()
            reply = client.command(
                b"MAIL FROM:<anne@example.org> BODY=BINARYMIME")
            assert reply.startswith(b"250")

    def test_mail_body_binarymime_rejected_when_disabled(
            self, plain_controller):
        with RawClient() as client:
            client.ehlo()
            reply = client.command(
                b"MAIL FROM:<anne@example.org> BODY=BINARYMIME")
            assert reply.startswith(b"501")


class TestBdatDelivery:
    def test_single_chunk_last(self, chunking_controller, handler):
        content = b"From: anne@example.org\r\n\r\nHello there!\r\n"
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(content, last=True).startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == content
        assert handler.box[0].original_content == content

    def test_binary_content_byte_exact(self, chunking_controller, handler):
        # NUL octets, dot-lines, and things that look like SMTP commands
        # must pass through untouched: no dot-unstuffing, no command parsing.
        content = (
            b"\x00\x01\x02 binary \xff\xfe\r\n"
            b".\r\n"
            b"..\r\n"
            b"NOOP\r\n"
            b"RSET\r\n"
            b"QUIT\r\n"
            b"\x00 trailing"
        )
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            client.send(b"BDAT %d LAST" % len(content) + BCRLF)
            # Fragment the content at awkward boundaries.
            client.send_slowly(content, step=7)
            assert client.reply().startswith(b"250")
            # The server must resume command parsing at exactly the right
            # byte position: this NOOP is a command, not content.
            assert client.command(b"NOOP").startswith(b"250")
            assert client.command(b"QUIT").startswith(b"221")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == content

    def test_fragmented_command_line_and_content(
            self, chunking_controller, handler):
        content = bytes(range(256)) * 3
        header = b"BDAT %d LAST\r\n" % len(content)
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            # Send the command line byte-by-byte, then the content in
            # odd-sized fragments.
            client.send_slowly(header, step=1)
            client.send_slowly(content, step=13)
            assert client.reply().startswith(b"250")
            assert client.command(b"NOOP").startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == content

    def test_multiple_chunks(self, chunking_controller, handler):
        chunks = [b"first\x00chunk", b"second\r\nchunk", b"third"]
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            for chunk in chunks[:-1]:
                assert client.bdat(chunk).startswith(b"250")
            assert client.bdat(chunks[-1], last=True).startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == b"".join(chunks)

    def test_zero_length_last(self, chunking_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(b"hello").startswith(b"250")
            # A zero-length LAST chunk is legal and finalizes the message.
            assert client.command(b"BDAT 0 LAST").startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == b"hello"

    def test_zero_length_only_chunk(self, chunking_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.command(b"BDAT 0 LAST").startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == b""

    def test_full_binarymime_flow(self, chunking_controller, handler):
        content = b"\x00\x01BINARY\xff\r\n.\r\n"
        with RawClient() as client:
            lines = client.ehlo()
            assert b"250-CHUNKING" in [line.strip() for line in lines]
            assert client.command(
                b"MAIL FROM:<anne@example.org> BODY=BINARYMIME"
            ).startswith(b"250")
            assert client.command(b"RCPT TO:<bart@example.org>").startswith(
                b"250")
            assert client.bdat(content, last=True).startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.content == content
        assert envelope.mail_from == "anne@example.org"
        assert envelope.rcpt_tos == ["bart@example.org"]


class TestBdatDataMixing:
    def test_data_after_bdat_rejected(self, chunking_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(b"hello").startswith(b"250")
            assert client.command(b"DATA").startswith(b"503")
            # RSET clears the half-finished BDAT transaction ...
            assert client.command(b"RSET").startswith(b"250")
            client.mail_rcpt()
            # ... and a normal DATA transaction works again.
            assert client.command(b"DATA").startswith(b"354")
            client.send(b"From: anne@example.org\r\n\r\nplain\r\n.\r\n")
            assert client.reply().startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == (
            b"From: anne@example.org\r\n\r\nplain\r\n")

    def test_rset_clears_bdat_state(self, chunking_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(b"hello").startswith(b"250")
            assert client.command(b"RSET").startswith(b"250")
            # New transaction with BDAT only contains post-RSET chunks.
            client.mail_rcpt()
            assert client.bdat(b"bye!", last=True).startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == b"bye!"


class TestBdatSizeLimit:
    @pytest.fixture
    def limited_controller(self, get_controller, handler):
        controller = get_controller(
            handler, enable_CHUNKING=True, data_size_limit=10)
        controller.start()
        Global.set_addr_from(controller)
        yield controller
        with suppress(AssertionError):
            controller.stop()

    def test_cumulative_size_limit(self, limited_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(b"123456").startswith(b"250")
            # 6 + 5 = 11 > 10: the declared bytes are consumed and discarded
            # before the 552 is sent.
            assert client.bdat(b"12345").startswith(b"552")
        catchup_delay()
        assert handler.box == []

    def test_failed_transaction_pipeline(self, limited_controller, handler):
        # Everything is pipelined in a single write: the server must consume
        # each declared chunk body (never executing binary as commands) and
        # resume command parsing at exactly the right position for the NOOP.
        payload = (
            b"BDAT 6\r\n" + b"123456" +
            b"BDAT 5\r\n" + b"NOOP\n" +            # 5 binary bytes, not commands
            b"BDAT 4 LAST\r\n" + b"RSET" +        # 4 binary bytes, not a command
            b"NOOP\r\n"
        )
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            client.send(payload)
            assert client.reply().startswith(b"250")   # first chunk OK
            assert client.reply().startswith(b"552")   # 6+5 > 10
            assert client.reply().startswith(b"552")   # failed transaction
            assert client.reply().startswith(b"250")   # NOOP
        catchup_delay()
        assert handler.box == []

    def test_size_limit_exact_boundary(self, limited_controller, handler):
        with RawClient() as client:
            client.ehlo()
            client.mail_rcpt()
            assert client.bdat(b"123456").startswith(b"250")
            # 6 + 4 = 10 is exactly at the limit, so it is accepted.
            assert client.bdat(b"7890", last=True).startswith(b"250")
        catchup_delay()
        assert len(handler.box) == 1
        assert handler.box[0].content == b"1234567890"


class TestBdatConnectionLoss:
    def test_disconnect_mid_chunk(self, chunking_controller, handler):
        client = RawClient()
        client.ehlo()
        client.mail_rcpt()
        client.send(b"BDAT 100 LAST" + BCRLF)
        client.send(b"only ten!")
        # Vanish without finishing the declared chunk.
        client.close()
        catchup_delay()
        # The incomplete message must not be delivered.
        assert handler.box == []

    def test_disconnect_before_last(self, chunking_controller, handler):
        client = RawClient()
        client.ehlo()
        client.mail_rcpt()
        assert client.bdat(b"hello").startswith(b"250")
        client.close()
        catchup_delay()
        assert handler.box == []
