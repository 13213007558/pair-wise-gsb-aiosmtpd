# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Tests for spooled DATA delivery (spool_threshold / MessageSpool)."""

import asyncio
import errno
import tempfile
from asyncio.transports import Transport
from contextlib import suppress
from typing import Callable, List, Tuple, cast

import pytest
from pytest_mock import MockFixture

import aiosmtpd.smtp
from aiosmtpd.smtp import SMTP as Server, MessageSpool
from aiosmtpd.testing.helpers import ReceivingHandler

BCRLF = b"\r\n"

# DATA lines as sent on the wire (RFC 5321 § 4.5.2 transparency applied) ...
SENT_LINES = [
    b"From: anne@example.com",
    b"To: bart@example.com",
    b"",
    b"..starts-with-dot",
    b"...triple-dot",
    b"..",
    b"plain line",
]
# ... and the corresponding "original content" (de-transparencied) bytes.
EXPECTED_CONTENT = BCRLF.join(
    [
        b"From: anne@example.com",
        b"To: bart@example.com",
        b"",
        b".starts-with-dot",
        b"..triple-dot",
        b".",
        b"plain line",
    ]
) + BCRLF


def make_session_bytes(*command_lines: bytes) -> bytes:
    return BCRLF.join(command_lines) + BCRLF


def mail_session(*data_lines: bytes) -> bytes:
    """A full HELO..QUIT session delivering data_lines as DATA content."""
    return make_session_bytes(
        b"HELO example.org",
        b"MAIL FROM: <anne@example.com>",
        b"RCPT TO: <bart@example.com>",
        b"DATA",
        BCRLF.join(data_lines) + BCRLF + b".",
        b"QUIT",
    )


def run_session(loop: asyncio.AbstractEventLoop, protocol: Server) -> None:
    """Run the handler coroutine to completion (client must have sent QUIT)."""
    with suppress(asyncio.CancelledError):
        loop.run_until_complete(protocol._handler_coroutine)


def flush_loop(loop: asyncio.AbstractEventLoop, delay: float = 0.1) -> None:
    """Let the event loop process everything that is currently pending."""
    loop.run_until_complete(asyncio.sleep(delay))


class SpoolRecordingHandler:
    """A handle_DATA_spooled hook recording what it gets."""

    def __init__(self) -> None:
        self.spools: List[MessageSpool] = []
        self.envelopes: list = []
        self.rolled: List[bool] = []
        self.contents: List[bytes] = []

    async def handle_DATA_spooled(self, server, session, envelope, spool):
        self.spools.append(spool)
        self.envelopes.append(envelope)
        self.rolled.append(spool.rolled)
        self.contents.append(spool.open().read())
        return "250 OK"


class TextRecordingHandler:
    """A handle_DATA_spooled hook using the decode_data-style text view."""

    def __init__(self) -> None:
        self.texts: List[str] = []

    async def handle_DATA_spooled(self, server, session, envelope, spool):
        with spool.open_text() as stream:
            self.texts.append(stream.read())
        return "250 OK"


@pytest.fixture
def transport_resp(mocker: MockFixture) -> Tuple[Transport, list]:
    responses: list = []
    mocked = mocker.Mock()
    mocked.write = responses.append
    return cast(Transport, mocked), responses


@pytest.fixture
def get_protocol(
    temp_event_loop: asyncio.AbstractEventLoop,
    transport_resp: Tuple[Transport, list],
) -> Callable[..., Server]:
    transport, _ = transport_resp

    def getter(*args, **kwargs) -> Server:
        proto = Server(*args, loop=temp_event_loop, **kwargs)
        proto.connection_made(transport)
        return proto

    return getter


@pytest.fixture
def spool_tracker(mocker: MockFixture) -> List[MessageSpool]:
    """Record every MessageSpool the SMTP server creates."""
    created: List[MessageSpool] = []

    class TrackingSpool(MessageSpool):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    mocker.patch.object(aiosmtpd.smtp, "MessageSpool", TrackingSpool)
    return created


class TestMessageSpool:
    def test_negative_threshold_rejected(self):
        with pytest.raises(ValueError):
            MessageSpool(-1)

    def test_in_memory_below_threshold(self, mocker: MockFixture):
        factory = mocker.patch("aiosmtpd.smtp.tempfile.TemporaryFile")
        spool = MessageSpool(1024)
        spool.write(b"abc")
        spool.write(b"def")
        assert not spool.rolled
        assert spool.buffered == 6
        assert spool.size == 6
        assert spool.open().read() == b"abcdef"
        factory.assert_not_called()
        spool.close()

    def test_exact_threshold_stays_in_memory(self):
        spool = MessageSpool(6)
        spool.write(b"abc")
        spool.write(b"def")
        assert not spool.rolled
        assert spool.max_buffered == 6
        spool.close()

    def test_rollover_preserves_content(self):
        spool = MessageSpool(4)
        for chunk in [b"ab", b"cd", b"ef", b"gh"]:
            spool.write(chunk)
        assert spool.rolled
        assert spool.buffered == 0
        assert spool.open().read() == b"abcdefgh"
        # Seekable: re-reading starts again from the beginning.
        assert spool.open().read() == b"abcdefgh"
        spool.close()

    def test_memory_bound(self):
        threshold = 10
        spool = MessageSpool(threshold)
        chunks = [b"x" * 8, b"y" * 8, b"z" * 100]
        for chunk in chunks:
            spool.write(chunk)
        # The in-memory buffer never exceeded the threshold ...
        assert spool.max_buffered <= threshold
        # ... and the largest single write is exactly the largest chunk.
        assert spool.max_write_chunk == 100
        assert spool.write_chunk_count == 3
        assert spool.open().read() == b"".join(chunks)
        spool.close()

    def test_write_failure_discards_partial_file(self, mocker: MockFixture):
        real = tempfile.TemporaryFile(mode="w+b")
        failing = mocker.Mock(wraps=real)
        failing.write.side_effect = OSError(errno.ENOSPC, "No space left")
        mocker.patch("aiosmtpd.smtp.tempfile.TemporaryFile", return_value=failing)
        spool = MessageSpool(0)
        with pytest.raises(OSError):
            spool.write(b"data")
        assert spool.closed
        # The partial temporary file was closed (=> removed) ...
        failing.close.assert_called_once()
        # ... and the spool is unusable now.
        with pytest.raises(ValueError):
            spool.write(b"more")
        with pytest.raises(ValueError):
            spool.open()

    def test_rollover_failure_closes_new_file(self, mocker: MockFixture):
        real = tempfile.TemporaryFile(mode="w+b")
        failing = mocker.Mock(wraps=real)
        failing.write.side_effect = OSError(errno.ENOSPC, "No space left")
        mocker.patch("aiosmtpd.smtp.tempfile.TemporaryFile", return_value=failing)
        spool = MessageSpool(2)
        spool.write(b"ab")  # fits in memory
        with pytest.raises(OSError):
            spool.write(b"cd")  # triggers the rollover, which fails
        assert spool.closed
        failing.close.assert_called_once()

    def test_close_removes_temp_file(self):
        spool = MessageSpool(0)
        spool.write(b"data")
        assert spool.rolled
        fileobj = spool._file
        spool.close()
        # Closing a TemporaryFile removes it from the filesystem.
        assert fileobj.closed
        # close() is idempotent.
        spool.close()
        assert spool.closed

    def test_detach_transfers_ownership(self):
        spool = MessageSpool(0)
        spool.write(b"data")
        stream = spool.detach()
        assert spool.detached
        spool.close()
        # The transaction-side close() must not close the detached stream.
        assert not stream.closed
        assert stream.read() == b"data"
        stream.close()

    def test_detach_in_memory(self):
        spool = MessageSpool(100)
        spool.write(b"data")
        stream = spool.detach()
        spool.close()
        assert stream.read() == b"data"
        stream.close()

    def test_write_after_detach_rejected(self):
        spool = MessageSpool(100)
        spool.detach()
        with pytest.raises(ValueError):
            spool.write(b"x")

    def test_detach_after_close_rejected(self):
        spool = MessageSpool(100)
        spool.close()
        with pytest.raises(ValueError):
            spool.detach()

    def test_open_text_decodes_without_newline_translation(self):
        content = "ligne \xe9\r\nsuite\r\n".encode("utf-8")
        spool = MessageSpool(0)
        spool.write(content)
        with spool.open_text("utf-8") as stream:
            assert stream.read() == "ligne \xe9\r\nsuite\r\n"
        # The text view is independent: closing it must not kill the spool.
        spool.open_text("utf-8").close()
        assert spool.open().read() == content
        spool.close()

    def test_open_text_in_memory(self):
        spool = MessageSpool(1024)
        spool.write(b"abc\r\n")
        with spool.open_text("ascii") as stream:
            assert stream.read() == "abc\r\n"
        spool.close()

    def test_check_decodable(self):
        spool = MessageSpool(0)
        spool.write(b"plain ascii\r\n")
        assert spool.check_decodable("ascii")
        spool.write(b"\xff")
        assert not spool.check_decodable("ascii")
        assert spool.check_decodable("utf-8", "surrogateescape")
        spool.close()

    def test_check_decodable_truncated_multibyte(self):
        spool = MessageSpool(0)
        # A truncated UTF-8 sequence at the very end of the content.
        spool.write(b"\xc3")
        assert not spool.check_decodable("utf-8")
        assert spool.check_decodable("utf-8", "surrogateescape")
        spool.close()

    def test_check_decodable_chunked(self):
        spool = MessageSpool(0)
        spool.write(b"a" * (aiosmtpd.smtp.SPOOL_DECODE_CHUNK_SIZE + 10))
        assert spool.check_decodable("ascii")
        spool.write(b"\x80")
        assert not spool.check_decodable("ascii")
        spool.close()

    def test_spool_dir_passed_to_tempfile(self, mocker: MockFixture, tmp_path):
        factory = mocker.patch(
            "aiosmtpd.smtp.tempfile.TemporaryFile", wraps=tempfile.TemporaryFile
        )
        spool = MessageSpool(0, dir=str(tmp_path))
        spool.write(b"x")
        factory.assert_called_once_with(mode="w+b", dir=str(tmp_path))
        spool.close()


class TestSpooledDATA:
    def test_small_message_stays_in_memory(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=2**20)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        assert b"250 OK\r\n" in responses
        # Delivered through the spool, but never rolled over to disk.
        assert handler.contents == [EXPECTED_CONTENT]
        assert handler.rolled == [False]
        # The classic envelope attributes stay empty on the spooled path.
        envelope = handler.envelopes[0]
        assert envelope.content is None
        assert envelope.original_content is None
        assert envelope.mail_from == "anne@example.com"
        assert envelope.rcpt_tos == ["bart@example.com"]
        # The transaction is over: the spool was discarded.
        assert len(spool_tracker) == 1
        assert all(spool.closed for spool in spool_tracker)

    def test_tiny_threshold_content_intact(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=1)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        # Switching from memory to a temporary file did not corrupt the
        # content, and dot-transparency was undone exactly once.
        assert handler.contents == [EXPECTED_CONTENT]
        assert handler.rolled == [True]
        # The spooled bytes are exactly what the classic in-memory path
        # would have produced as original_content.
        classic = ReceivingHandler()
        classic_protocol = get_protocol(classic)
        classic_protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, classic_protocol)
        assert classic.box[0].original_content == EXPECTED_CONTENT
        assert all(spool.closed for spool in spool_tracker)

    def test_memory_bound_via_server(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        long_line = b"x" * 500
        lines = [b"short", long_line, b"another", b"..dot"]
        expected = BCRLF.join([b"short", long_line, b"another", b".dot"]) + BCRLF
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=10)
        protocol.data_received(mail_session(*lines))
        run_session(temp_event_loop, protocol)
        (spool,) = spool_tracker
        # Memory bound: never more than "threshold" content bytes in RAM ...
        assert spool.max_buffered <= 10
        # ... and the file is written line by line, each chunk bounded by
        # the server's line length limit.
        assert spool.max_write_chunk == len(long_line) + len(BCRLF)
        assert spool.max_write_chunk <= Server.line_length_limit
        assert spool.write_chunk_count == len(lines)
        assert spool.rolled
        assert spool.buffered == 0
        assert handler.contents == [expected]
        assert spool.closed

    def test_spool_write_failure_then_second_mail_ok(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker, mocker
    ):
        flag = {"fail": True}
        flakies: list = []
        real_temporary_file = tempfile.TemporaryFile

        class FlakyFile:
            """A TemporaryFile stand-in whose writes fail while flagged."""

            def __init__(self):
                self._real = real_temporary_file(mode="w+b")
                self.close_called = False

            def write(self, data):
                if flag["fail"]:
                    raise OSError(errno.ENOSPC, "No space left on device")
                return self._real.write(data)

            def close(self):
                self.close_called = True
                return self._real.close()

            def __getattr__(self, name):
                return getattr(self._real, name)

        def factory(*args, **kwargs):
            flaky = FlakyFile()
            flakies.append(flaky)
            return flaky

        mocker.patch("aiosmtpd.smtp.tempfile.TemporaryFile", side_effect=factory)

        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        _, responses = transport_resp

        # First mail: writing the temporary file fails (disk full).
        protocol.data_received(
            make_session_bytes(
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                BCRLF.join(SENT_LINES) + BCRLF + b".",
            )
        )
        flush_loop(temp_event_loop)
        assert b"452 4.3.1 Insufficient system storage\r\n" in responses
        assert handler.contents == []
        # The partial temporary file was cleaned up deterministically.
        assert len(flakies) == 1
        assert flakies[0].close_called
        assert all(spool.closed for spool in spool_tracker)

        # Second mail on the same connection: delivered normally.
        flag["fail"] = False
        protocol.data_received(
            make_session_bytes(
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                BCRLF.join(SENT_LINES) + BCRLF + b".",
                b"QUIT",
            )
        )
        run_session(temp_event_loop, protocol)
        assert handler.contents == [EXPECTED_CONTENT]
        assert b"250 OK\r\n" in responses
        # Every temporary file -- the failed and the successful one -- was
        # disposed of by the transaction.
        assert all(flaky.close_called for flaky in flakies)
        assert all(spool.closed for spool in spool_tracker)

    def test_handler_exception_cleans_up(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        class ExplodingHandler:
            async def handle_DATA_spooled(self, server, session, envelope, spool):
                raise RuntimeError("boom")

        protocol = get_protocol(ExplodingHandler(), spool_threshold=0)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        assert b"500 Error: (RuntimeError) boom\r\n" in responses
        assert len(spool_tracker) == 1
        assert all(spool.closed for spool in spool_tracker)

    def test_client_disconnect_before_terminator(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(
            make_session_bytes(
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"partial data, no terminator",
            )
        )
        flush_loop(temp_event_loop)
        # The spool exists and holds the partial data.
        (spool,) = spool_tracker
        assert not spool.closed
        # The client vanishes before sending <CRLF>.<CRLF>.
        protocol.eof_received()
        run_session(temp_event_loop, protocol)
        assert spool.closed
        assert protocol._spool is None
        assert handler.contents == []

    def test_connection_lost_mid_data(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(
            make_session_bytes(
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"partial data, no terminator",
            )
        )
        flush_loop(temp_event_loop)
        (spool,) = spool_tracker
        protocol.connection_lost(None)
        run_session(temp_event_loop, protocol)
        assert spool.closed
        assert protocol._spool is None
        assert handler.contents == []

    def test_rset_discards_transaction_spool(
        self, temp_event_loop, transport_resp, get_protocol
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(make_session_bytes(b"HELO example.org"))
        flush_loop(temp_event_loop)
        # A spool still owned by the transaction ...
        spool = MessageSpool(0)
        spool.write(b"in-flight data")
        assert spool.rolled
        protocol._spool = spool
        # ... is deterministically discarded when the transaction resets.
        protocol.data_received(make_session_bytes(b"RSET", b"QUIT"))
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        assert b"250 OK\r\n" in responses
        assert spool.closed
        assert protocol._spool is None

    def test_rset_after_too_much_data(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0, data_size_limit=64)
        protocol.data_received(
            make_session_bytes(
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"x" * 1000 + BCRLF + b".",
                b"RSET",
                b"QUIT",
            )
        )
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        # The total-size rule is still enforced in spool mode ...
        assert b"552 Error: Too much mail data\r\n" in responses
        # ... and the session stays usable afterwards.
        assert responses[-2] == b"250 OK\r\n"
        assert handler.contents == []
        assert all(spool.closed for spool in spool_tracker)

    def test_line_too_long(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(
            make_session_bytes(
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"y" * 1500 + BCRLF + b".",
                b"QUIT",
            )
        )
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        # The line-length rule is still enforced in spool mode.
        assert b"500 Line too long (see RFC5321 4.5.3.1.6)\r\n" in responses
        assert handler.contents == []
        assert all(spool.closed for spool in spool_tracker)

    def test_detach_transfers_ownership(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        class DetachingHandler:
            def __init__(self):
                self.spool = None
                self.stream = None

            async def handle_DATA_spooled(self, server, session, envelope, spool):
                self.spool = spool
                self.stream = spool.detach()
                return "250 OK"

        handler = DetachingHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        assert b"250 OK\r\n" in responses
        # The transaction ended (the spool was closed server-side) but the
        # detached stream is still owned -- and usable -- by the handler.
        assert handler.spool.closed
        assert handler.spool.detached
        assert not handler.stream.closed
        assert handler.stream.read() == EXPECTED_CONTENT
        handler.stream.close()

    def test_decode_data_text_view(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = TextRecordingHandler()
        protocol = get_protocol(handler, decode_data=True, spool_threshold=0)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        # The text view decodes the original bytes; CRLFs are preserved.
        assert handler.texts == [EXPECTED_CONTENT.decode("ascii")]
        assert all(spool.closed for spool in spool_tracker)

    def test_decode_data_strict_ascii_rejects_non_ascii(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = SpoolRecordingHandler()
        protocol = get_protocol(handler, decode_data=True, spool_threshold=0)
        protocol.data_received(mail_session(b"caf\xc3\xa9"))
        run_session(temp_event_loop, protocol)
        _, responses = transport_resp
        assert b"500 Error: strict ASCII mode\r\n" in responses
        assert handler.contents == []
        assert all(spool.closed for spool in spool_tracker)

    def test_decode_data_smtputf8_text_view(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = TextRecordingHandler()
        protocol = get_protocol(
            handler,
            decode_data=True,
            enable_SMTPUTF8=True,
            spool_threshold=0,
        )
        protocol.data_received(mail_session("caf\xe9".encode("utf-8")))
        run_session(temp_event_loop, protocol)
        assert handler.texts == ["caf\xe9\r\n"]
        assert all(spool.closed for spool in spool_tracker)

    def test_legacy_handler_keeps_bytes_path(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker, mocker
    ):
        factory = mocker.patch("aiosmtpd.smtp.tempfile.TemporaryFile")
        handler = ReceivingHandler()
        # spool_threshold is set, but the handler has no handle_DATA_spooled.
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        # Classic delivery: full bytes on the envelope, no spool involved.
        assert handler.box[0].content == EXPECTED_CONTENT
        assert handler.box[0].original_content == EXPECTED_CONTENT
        assert spool_tracker == []
        factory.assert_not_called()

    def test_spooled_hook_takes_precedence_when_enabled(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = BothHooksHandler()
        protocol = get_protocol(handler, spool_threshold=0)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        assert handler.spooled == 1
        assert handler.classic == 0

    def test_default_without_threshold_uses_bytes_hook(
        self, temp_event_loop, transport_resp, get_protocol, spool_tracker
    ):
        handler = BothHooksHandler()
        protocol = get_protocol(handler)
        protocol.data_received(mail_session(*SENT_LINES))
        run_session(temp_event_loop, protocol)
        assert handler.classic == 1
        assert handler.spooled == 0
        assert spool_tracker == []


class BothHooksHandler:
    def __init__(self) -> None:
        self.classic = 0
        self.spooled = 0

    async def handle_DATA(self, server, session, envelope):
        self.classic += 1
        return "250 OK"

    async def handle_DATA_spooled(self, server, session, envelope, spool):
        self.spooled += 1
        return "250 OK"
