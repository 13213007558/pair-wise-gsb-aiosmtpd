# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test the optional DATA spool mode (spool_threshold + handle_DATA_stream)."""

import socket
import tempfile
import time
from contextlib import suppress
from smtplib import SMTP as SMTPClient, SMTPDataError
from typing import Callable, Generator, List, Optional

import pytest
from pytest_mock import MockFixture

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import MessageStream, SMTP as Server
from aiosmtpd.testing.helpers import send_recv

from .conftest import Global


BCRLF = b"\r\n"


# region #### Test Helpers ############################################################


class StreamHandler:
    """Handler implementing the streaming DATA interface."""

    def __init__(self):
        self.streams: List[MessageStream] = []
        self.contents: List[bytes] = []
        self.envelopes: list = []
        self.rolled: List[bool] = []

    async def handle_DATA_stream(self, server, session, envelope, stream):
        self.streams.append(stream)
        self.envelopes.append(envelope)
        self.rolled.append(stream.rolled_to_disk)
        self.contents.append(stream.read())
        return "250 OK"


class LegacyHandler:
    """Handler implementing only the classic bytes interface."""

    def __init__(self):
        self.envelopes: list = []

    async def handle_DATA(self, server, session, envelope):
        self.envelopes.append(envelope)


class SpyingSpool(tempfile.SpooledTemporaryFile):
    """SpooledTemporaryFile that records statistics about itself."""

    instances: List["SpyingSpool"] = []
    write_sizes: List[int] = []
    max_inmemory: int = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).instances.append(self)

    def write(self, s):
        if not self._rolled:
            # Peak in-memory buffer size right after this write lands
            # (i.e. before SpooledTemporaryFile gets a chance to roll over).
            peak = self._file.tell() + len(s)
            type(self).max_inmemory = max(type(self).max_inmemory, peak)
        type(self).write_sizes.append(len(s))
        return super().write(s)

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.write_sizes = []
        cls.max_inmemory = 0


class FlakySpool(tempfile.SpooledTemporaryFile):
    """SpooledTemporaryFile whose writes fail (simulating a full disk)."""

    fail_writes: bool = True
    instances: List["FlakySpool"] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).instances.append(self)

    def write(self, s):
        if type(self).fail_writes:
            raise OSError(28, "No space left on device")
        return super().write(s)

    @classmethod
    def reset(cls):
        cls.fail_writes = True
        cls.instances = []


def make_message(*lines: bytes) -> bytes:
    return BCRLF.join(lines)


def wait_for(predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# endregion

# region #### Fixtures #################################################################


@pytest.fixture
def make_controller(
    get_controller: Callable,
) -> Generator[Callable[..., Controller], None, None]:
    controller: Optional[Controller] = None

    def factory(handler, **kwargs) -> Controller:
        nonlocal controller
        controller = get_controller(handler, **kwargs)
        controller.start()
        Global.set_addr_from(controller)
        return controller

    yield factory

    if controller is not None:
        with suppress(AssertionError):
            controller.stop()


@pytest.fixture
def client_of() -> Generator[Callable[[Controller], SMTPClient], None, None]:
    clients: List[SMTPClient] = []

    def factory(controller: Controller) -> SMTPClient:
        client = SMTPClient(controller.hostname, controller.port)
        clients.append(client)
        return client

    yield factory

    for client in clients:
        with suppress(Exception):
            client.quit()
        with suppress(Exception):
            client.close()


# endregion


class TestSpoolMode:
    def test_small_message_stays_in_memory(self, make_controller, client_of):
        handler = StreamHandler()
        controller = make_controller(handler, spool_threshold=4096)
        client = client_of(controller)
        msg = make_message(
            b"From: anne@example.com",
            b"To: bart@example.com",
            b"",
            b"small body",
        )
        refused = client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert refused == {}
        assert handler.contents == [msg + BCRLF]
        # A small message must never touch the disk
        assert handler.rolled == [False]
        # The server closes the stream once the hook has returned
        assert handler.streams[0].closed
        # Spool mode does not populate the legacy content attributes
        envelope = handler.envelopes[0]
        assert envelope.content is None
        assert envelope.original_content is None

    def test_rollover_keeps_content_intact(self, make_controller, client_of):
        handler = StreamHandler()
        # Tiny threshold: forces rollover to a temporary file mid-message
        controller = make_controller(handler, spool_threshold=10)
        client = client_of(controller)
        msg = make_message(
            b"From: anne@example.com",
            b"To: bart@example.com",
            b"Subject: rollover",
            b"",
            b".starts with a dot",
            b"..starts with two dots",
            b"x" * 100,
            b"y" * 100,
            b"final line",
        )
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        # Content must survive the memory -> file switch without corruption,
        # with dot-transparency undone exactly once (smtplib dot-stuffs when
        # sending, the server de-transparencies when receiving).
        assert handler.contents == [msg + BCRLF]
        assert handler.rolled == [True]
        assert handler.streams[0].closed

    def test_memory_bound(
        self, mocker: MockFixture, make_controller, client_of
    ):
        SpyingSpool.reset()
        mocker.patch.object(tempfile, "SpooledTemporaryFile", SpyingSpool)
        handler = StreamHandler()
        threshold = 64
        controller = make_controller(handler, spool_threshold=threshold)
        client = client_of(controller)
        msg = make_message(
            b"From: anne@example.com",
            *[(b"line %02d " % i) + b"z" * 90 for i in range(20)]
        )
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert handler.contents == [msg + BCRLF]
        assert handler.rolled == [True]
        # The message is streamed line by line: no single write to the spool
        # may exceed the maximum DATA line length.
        max_chunk = max(SpyingSpool.write_sizes)
        assert max_chunk <= Server.line_length_limit
        # The in-memory buffer can never exceed the threshold plus the
        # largest single write chunk.
        assert SpyingSpool.max_inmemory <= threshold + max_chunk

    def test_spool_write_failure_then_recovery(
        self, mocker: MockFixture, make_controller, client_of
    ):
        FlakySpool.reset()
        mocker.patch.object(tempfile, "SpooledTemporaryFile", FlakySpool)
        handler = StreamHandler()
        controller = make_controller(handler, spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"body " * 40)
        # First attempt: the temporary file cannot be written -> 451
        with pytest.raises(SMTPDataError) as exc:
            client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert exc.value.smtp_code == 451
        # The failed transaction released its temporary file
        assert FlakySpool.instances
        assert all(inst.closed for inst in FlakySpool.instances)
        assert handler.contents == []
        # Disk "freed up" again: a second mail on the same connection must
        # be delivered normally.
        FlakySpool.fail_writes = False
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert handler.contents == [msg + BCRLF]

    def test_handler_exception_closes_spool(self, make_controller, client_of):
        streams: List[MessageStream] = []

        class BoomHandler:
            async def handle_DATA_stream(
                self, server, session, envelope, stream
            ):
                streams.append(stream)
                raise RuntimeError("boom")

        controller = make_controller(BoomHandler(), spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 100)
        with pytest.raises(SMTPDataError) as exc:
            client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert exc.value.smtp_code == 500
        assert streams[0].closed
        # The session survives a handler exception
        code, _ = client.noop()
        assert code == 250

    def test_client_disconnect_before_terminator(
        self, mocker: MockFixture, make_controller
    ):
        SpyingSpool.reset()
        mocker.patch.object(tempfile, "SpooledTemporaryFile", SpyingSpool)
        handler = StreamHandler()
        controller = make_controller(handler, spool_threshold=10)
        with socket.socket() as sock:
            sock.connect((controller.hostname, controller.port))
            assert send_recv(sock, b"EHLO example.com").startswith(b"250")
            rslt = send_recv(sock, b"MAIL FROM: <anne@example.com>")
            assert rslt.startswith(b"250")
            rslt = send_recv(sock, b"RCPT TO: <bart@example.com>")
            assert rslt.startswith(b"250")
            assert send_recv(sock, b"DATA").startswith(b"354")
            # Send enough to force rollover, then vanish without terminator
            sock.sendall(b"x" * 500 + BCRLF)
        assert wait_for(
            lambda: bool(SpyingSpool.instances)
            and all(inst.closed for inst in SpyingSpool.instances)
        )
        assert handler.contents == []

    def test_rset_after_spooled_data(self, make_controller, client_of):
        handler = StreamHandler()
        controller = make_controller(handler, spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 100)
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert handler.streams[0].closed
        code, _ = client.rset()
        assert code == 250
        # Transaction state is clean: another spooled mail can be delivered
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert handler.contents == [msg + BCRLF, msg + BCRLF]
        assert all(stream.closed for stream in handler.streams)

    def test_ownership_transfer(self, make_controller, client_of):
        retained: List[MessageStream] = []

        class RetainingHandler:
            async def handle_DATA_stream(
                self, server, session, envelope, stream
            ):
                stream.take_ownership()
                retained.append(stream)
                return "250 OK"

        controller = make_controller(RetainingHandler(), spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 100)
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        stream = retained[0]
        # The server must not close a stream whose ownership was transferred
        assert not stream.closed
        assert stream.rolled_to_disk
        stream.seek(0)
        assert stream.read() == msg + BCRLF
        # The handler is now responsible for cleanup
        stream.close()
        assert stream.closed

    def test_legacy_handler_keeps_bytes_path(
        self, caplog, make_controller, client_of
    ):
        handler = LegacyHandler()
        controller = make_controller(handler, spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 100)
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert len(handler.envelopes) == 1
        envelope = handler.envelopes[0]
        assert envelope.content == msg + BCRLF
        assert envelope.original_content == msg + BCRLF
        assert "spool mode is disabled" in caplog.text

    def test_decode_data_does_not_materialize(self, make_controller, client_of):
        handler = StreamHandler()
        controller = make_controller(
            handler, spool_threshold=10, decode_data=True
        )
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 100)
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        # decode_data has no effect in spool mode: the stream always carries
        # the raw bytes and the legacy attributes stay empty.
        assert handler.contents == [msg + BCRLF]
        assert handler.envelopes[0].content is None
        assert handler.envelopes[0].original_content is None

    def test_size_limit_still_enforced(self, make_controller, client_of):
        handler = StreamHandler()
        controller = make_controller(
            handler, spool_threshold=10, data_size_limit=100
        )
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 500)
        with pytest.raises(SMTPDataError) as exc:
            client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert exc.value.smtp_code == 552
        assert handler.contents == []

    def test_line_length_limit_still_enforced(
        self, make_controller, client_of
    ):
        handler = StreamHandler()
        controller = make_controller(handler, spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"From: a@example.com", b"", b"x" * 1100)
        with pytest.raises(SMTPDataError) as exc:
            client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert exc.value.smtp_code == 500
        assert handler.contents == []

    def test_negative_threshold_rejected(self, temp_event_loop):
        with pytest.raises(ValueError):
            Server(LegacyHandler(), spool_threshold=-1, loop=temp_event_loop)

    def test_message_stream_seek_tell_readline(
        self, make_controller, client_of
    ):
        seen = {}

        class PokingHandler:
            async def handle_DATA_stream(
                self, server, session, envelope, stream
            ):
                seen["first"] = stream.readline()
                seen["pos"] = stream.tell()
                stream.seek(0)
                seen["again"] = stream.readline()
                stream.seek(0, 2)
                seen["end"] = stream.tell()
                return "250 OK"

        controller = make_controller(PokingHandler(), spool_threshold=10)
        client = client_of(controller)
        msg = make_message(b"first line", b"second line " + b"y" * 50)
        client.sendmail("anne@example.com", ["bart@example.com"], msg)
        assert seen["first"] == b"first line" + BCRLF
        assert seen["pos"] == len(b"first line" + BCRLF)
        assert seen["again"] == seen["first"]
        assert seen["end"] == len(msg + BCRLF)
