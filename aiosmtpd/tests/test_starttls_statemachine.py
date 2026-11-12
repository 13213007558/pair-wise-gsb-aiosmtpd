# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
STARTTLS state-transition tests driven entirely over in-memory transports.

No listening service (and therefore no socket/port binding) is used.  The only
component being faked is the TLS handshake: ``asyncio.sslproto.SSLProtocol`` is
replaced by :class:`FakeSSLProtocol`, whose success/failure/cancellation can be
controlled per test.  Everything else -- SMTP command parsing, the STARTTLS
transport reconfiguration in :meth:`SMTP.smtp_STARTTLS`, and the session/
envelope rebuild performed by :meth:`SMTP.connection_made` -- runs the real
production code.
"""

import asyncio
import ssl
from contextlib import suppress
from typing import Any, Callable, List, NamedTuple, Optional, Tuple

import pytest
from pytest_mock import MockerFixture

from aiosmtpd.smtp import (
    AuthResult,
    Envelope,
    LoginPassword,
    SMTP,
    TLSSetupException,
)
from aiosmtpd.testing.statuscodes import SMTP_STATUS_CODES as S

BCRLF = b"\r\n"

#: Outcomes the fake TLS handshake can be instructed to produce.
HANDSHAKE_SUCCESS = "success"
HANDSHAKE_FAIL = "fail"
HANDSHAKE_CANCEL = "cancel"


# region #### In-memory transport + handshake double ################################


class MemoryTransport(asyncio.BaseTransport):
    """
    A plain in-memory transport that records every byte written back to the
    peer.  It stands in for the real socket transport before STARTTLS and for
    the low-level transport that ``SSLProtocol`` wraps.
    """

    def __init__(self, protocol: asyncio.Protocol, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self._protocol = protocol
        self._loop = loop
        self.closed = False
        self.written: List[bytes] = []

    def get_protocol(self) -> asyncio.Protocol:
        return self._protocol

    def set_protocol(self, protocol: asyncio.Protocol) -> None:
        self._protocol = protocol

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    def writelines(self, list_of_data: List[bytes]) -> None:
        for data in list_of_data:
            self.write(data)

    def write_eof(self) -> None:
        pass

    def is_closing(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        info = {
            "peername": ("127.0.0.1", 54321),
            "sockname": ("127.0.0.1", 25),
        }
        return info.get(name, default)


class FakeSSLProtocol:
    """
    Handshake double for :class:`asyncio.sslproto.SSLProtocol`.

    Only the SSL handshake itself is simulated; the app still talks to the real
    :class:`SMTP` protocol through the stdlib ``_SSLProtocolTransport``.  The
    double reproduces the exact surface ``smtp.py`` relies on:

      * ``_app_transport`` exists right after construction (``smtp_STARTTLS``
        reads it immediately),
      * the handshake completes on a later loop iteration, just like the real
        implementation,
      * success re-invokes ``app_protocol.connection_made()`` and resolves the
        waiter; failure/cancellation reject or cancel it.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        app_protocol: SMTP,
        sslcontext: ssl.SSLContext,
        waiter: asyncio.Future,
        server_side: bool,
        outcome: str,
    ):
        from asyncio.sslproto import _SSLProtocolTransport

        self._loop = loop
        self._app_protocol = app_protocol
        self._waiter = waiter
        self._outcome = outcome
        self._transport: Optional[MemoryTransport] = None
        self._closed = False
        self._extra = dict(
            sslcontext=sslcontext,
            peercert=None,
            cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            compression=None,
            ssl_object=object(),
        )
        self._app_transport = _SSLProtocolTransport(self._loop, self)

    # Surface used by _SSLProtocolTransport
    def _get_app_transport(self):
        return self._app_transport

    def _is_transport_closing(self) -> bool:
        return self._closed

    def _set_app_protocol(self, protocol: asyncio.Protocol) -> None:
        self._app_protocol = protocol

    def _get_extra_info(self, name: str, default: Any = None) -> Any:
        return self._extra.get(name, default)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport
        # The real SSLProtocol finishes the handshake asynchronously, after
        # smtp_STARTTLS has suspended on the waiter.
        self._loop.call_soon(self._complete_handshake)

    def _complete_handshake(self) -> None:
        assert self._transport is not None
        if self._outcome == HANDSHAKE_SUCCESS:
            self._app_protocol.connection_made(self._get_app_transport())
            if not self._waiter.done():
                self._waiter.set_result(None)
        elif self._outcome == HANDSHAKE_FAIL:
            self._closed = True
            self._app_transport._closed = True
            self._transport.close()
            if not self._waiter.done():
                self._waiter.set_exception(ssl.SSLError("fake handshake failure"))
        elif self._outcome == HANDSHAKE_CANCEL:
            self._waiter.cancel()
        else:  # pragma: no cover
            raise AssertionError(f"unknown outcome {self._outcome!r}")

    def _write_appdata(self, data) -> None:
        # Pretend the TLS layer encrypted and shipped the bytes: forward them
        # straight to the in-memory low-level transport so tests can observe
        # what the server said "inside" the TLS session.
        assert self._transport is not None
        for chunk in data:
            self._transport.write(bytes(chunk))

    def _start_shutdown(self) -> None:
        # Invoked by _SSLProtocolTransport.close(); nothing to actually flush
        # over an in-memory transport.
        self._closed = True

    def abort(self) -> None:
        self._closed = True
        if self._transport is not None:
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        # Post-handshake decrypted bytes go back to the real SMTP protocol.
        self._app_protocol.data_received(data)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._closed = True
        if self._app_transport is not None:
            self._app_transport._closed = True


# endregion


# region #### Recording handler ######################################################


class Delivery(NamedTuple):
    session: Any
    envelope: Envelope


class RecordingHandler:
    """Remembers every envelope actually delivered plus handshake decisions."""

    def __init__(self, starttls_result: Optional[bool] = None):
        self.box: List[Delivery] = []
        self.exceptions: List[Exception] = []
        self.starttls_result = starttls_result

    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        session.host_name = hostname
        return responses

    async def handle_DATA(self, server, session, envelope) -> str:
        self.box.append(Delivery(session=session, envelope=envelope))
        return "250 OK"

    async def handle_exception(self, error: Exception) -> str:
        self.exceptions.append(error)
        return "500 exception captured"

    def handle_STARTTLS(self, server, session, envelope) -> bool:
        if self.starttls_result is None:
            return True
        return self.starttls_result


def always_authenticate(server, session, envelope, mechanism, auth_data):
    return AuthResult(success=True, auth_data=LoginPassword(b"alice", b"secret"))


# endregion


# region #### Fixtures ###############################################################


@pytest.fixture
def event_loop_factory():
    created: List[asyncio.AbstractEventLoop] = []

    def factory() -> asyncio.AbstractEventLoop:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        created.append(loop)
        return loop

    yield factory

    for loop in created:
        loop.close()


@pytest.fixture
def tls_harness(mocker: MockerFixture, event_loop_factory):
    """
    Builds a connected :class:`SMTP` protocol on top of an in-memory transport
    with the SSL handshake double installed.

    Returns a small driver object exposing ``send()`` and the raw responses.
    """

    class Driver:
        def __init__(self, outcome: str, handler: RecordingHandler, **server_kw):
            self.loop = event_loop_factory()
            self.handler = handler
            self.outcome = outcome
            self._real_sslproto = None
            self.server: SMTP
            self.transport: MemoryTransport
            self._build(outcome, handler, server_kw)

        def _build(self, outcome, handler, server_kw):
            self._real_sslproto = mocker.patch(
                "aiosmtpd.smtp.sslproto.SSLProtocol",
                side_effect=self._fake_factory(outcome),
            )
            self.server = SMTP(
                handler,
                tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
                auth_require_tls=False,
                authenticator=always_authenticate,
                loop=self.loop,
                **server_kw,
            )
            self.transport = MemoryTransport(self.server, self.loop)
            self.server.connection_made(self.transport)

        def _fake_factory(self, outcome: str) -> Callable:
            def factory(loop, app_protocol, sslcontext, waiter, server_side=False):
                return FakeSSLProtocol(
                    loop, app_protocol, sslcontext, waiter, server_side, outcome
                )

            return factory

        def _pump(self) -> None:
            for _ in range(5):
                self.loop.run_until_complete(asyncio.sleep(0))

        def send(self, *lines: bytes) -> List[bytes]:
            """Feed command lines and return every response produced so far."""
            before = len(self.transport.written)
            self.server.data_received(BCRLF.join(lines) + BCRLF)
            self._pump()
            return self.transport.written[before:]

        def run(self, coro):
            return self.loop.run_until_complete(coro)

        def teardown(self) -> None:
            # Cancel the still-running client loop coroutine like a real
            # connection_lost() would, then close every transport so the
            # stdlib _SSLProtocolTransport.__del__ does not emit a
            # "unclosed transport" ResourceWarning.
            task = self.server._handler_coroutine
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    self.loop.run_until_complete(task)
            if self.server._tls_protocol is not None:
                self.server._tls_protocol.connection_lost(None)
            if self.server.transport is not None:
                with suppress(Exception):
                    self.server.transport.close()
            self.transport.close()
            self._pump()

    yield Driver


@pytest.fixture
def driver(tls_harness):
    drivers: List["Driver"] = []

    def factory(outcome: str = HANDSHAKE_SUCCESS, **server_kw) -> "Driver":
        handler = RecordingHandler(server_kw.pop("starttls_result", None))
        d = tls_harness(outcome, handler, **server_kw)
        drivers.append(d)
        return d

    yield factory

    for d in drivers:
        d.teardown()


def _status(line: bytes) -> Tuple[int, bytes]:
    """Parse an SMTP response line (handles ``250-`` continuations)."""
    line = line.strip()
    code = int(line[:3])
    message = line[4:] if len(line) > 4 else b""
    return code, message


# endregion


# region #### Cleartext phase is real ################################################


class TestCleartextPhase:
    def test_ehlo_advertises_starttls_and_auth(self, driver):
        d = driver()
        responses = d.send(b"EHLO plain.example")
        codes = [_status(line)[0] for line in responses]
        assert codes[0] == 220  # greeting is part of the first pumped output
        joined = b"".join(responses)
        assert b"250-STARTTLS" in joined
        assert b"250-AUTH" in joined
        assert d.server.session.host_name == "plain.example"
        assert d.server.session.extended_smtp is True

    def test_auth_succeeds_in_cleartext_when_allowed(self, driver):
        d = driver()
        d.send(b"EHLO plain.example")
        responses = d.send(b"AUTH PLAIN AHRlc3QAdGVzdA==")
        assert _status(responses[-1]) == (235, S.S235_AUTH_SUCCESS.mesg)
        assert d.server.session.authenticated is True
        assert d.server.session.auth_data == LoginPassword(b"alice", b"secret")

    def test_partial_transaction_populates_envelope(self, driver):
        d = driver()
        d.send(b"EHLO plain.example", b"MAIL FROM:<anne@example.com>")
        responses = d.send(b"RCPT TO:<bob@example.com>")
        assert _status(responses[-1]) == (250, b"OK")
        assert d.server.envelope.mail_from == "anne@example.com"
        assert d.server.envelope.rcpt_tos == ["bob@example.com"]


# endregion


# region #### Successful upgrade resets protocol state ###############################


class TestSuccessfulUpgrade:
    def test_handshake_double_replaces_only_the_handshake(self, driver):
        # Sanity check: command parsing still goes through the real SMTP code.
        d = driver()
        d.send(b"EHLO plain.example")
        responses = d.send(b"STARTTLS")
        assert _status(responses[-1]) == (220, S.S220_READY_TLS.mesg)
        assert isinstance(d.server._tls_protocol, FakeSSLProtocol)
        assert d.server.session.ssl is not None

    def test_upgrade_clears_ehlo_auth_and_partial_transaction(self, driver):
        d = driver()
        d.send(
            b"EHLO plain.example",
            b"AUTH PLAIN AHRlc3QAdGVzdA==",
            b"MAIL FROM:<anne@example.com>",
            b"RCPT TO:<bob@example.com>",
        )
        # Preconditions from the cleartext phase.
        assert d.server.session.authenticated is True
        assert d.server.session.host_name == "plain.example"
        assert d.server.envelope.rcpt_tos == ["bob@example.com"]

        d.send(b"STARTTLS")

        # A brand new Session and Envelope are created by connection_made().
        assert d.server.session.host_name is None
        assert d.server.session.extended_smtp is False
        assert d.server.session.authenticated is None
        assert d.server.session.auth_data is None
        assert d.server.session.ssl is not None
        assert d.server.envelope.mail_from is None
        assert d.server.envelope.rcpt_tos == []

    def test_server_configuration_survives_upgrade(self, driver):
        d = driver(data_size_limit=12345, enable_SMTPUTF8=True)
        tls_context = d.server.tls_context
        authenticator = d.server._authenticator
        d.send(b"EHLO plain.example", b"STARTTLS")
        # The same SMTP object keeps its configuration.
        assert d.server.tls_context is tls_context
        assert d.server._authenticator is authenticator
        assert d.server.data_size_limit == 12345
        assert d.server.enable_SMTPUTF8 is True
        assert d.server._auth_require_tls is False

    def test_pipelined_cleartext_bytes_after_starttls_are_discarded(self, driver):
        d = driver()
        d.send(b"EHLO plain.example")
        # RFC 3207: any data buffered before the handshake is discarded.
        d.server.data_received(b"STARTTLS\r\nNOOP\r\n")
        d._pump()
        assert bytes(d.server._reader._buffer) == b""
        joined = b"".join(d.transport.written)
        # The smuggled NOOP must not have produced a 250 response.
        assert joined.count(b"250 OK") == 0

    def test_must_re_ehlo_before_auth_or_mail(self, driver):
        d = driver()
        d.send(b"EHLO plain.example", b"AUTH PLAIN AHRlc3QAdGVzdA==")
        d.send(b"STARTTLS")

        auth_resp = d.send(b"AUTH PLAIN AHRlc3QAdGVzdA==")
        assert _status(auth_resp[-1]) == (503, S.S503_EHLO_FIRST.mesg)
        mail_resp = d.send(b"MAIL FROM:<anne@example.com>")
        assert _status(mail_resp[-1]) == (503, S.S503_HELO_FIRST.mesg)
        # The cleartext identity must not leak into the new session.
        assert d.server.session.authenticated is None

    def test_re_ehlo_re_advertises_capabilities_without_starttls(self, driver):
        d = driver()
        d.send(b"EHLO plain.example", b"STARTTLS")
        responses = d.send(b"EHLO secure.example")
        joined = b"".join(responses)
        assert b"250-AUTH" in joined
        # STARTTLS is no longer offered once the transport is encrypted.
        assert b"STARTTLS" not in joined
        assert d.server.session.host_name == "secure.example"

    def test_renegotiated_transaction_delivers_fresh_envelope(self, driver):
        d = driver()
        d.send(
            b"EHLO plain.example",
            b"AUTH PLAIN AHRlc3QAdGVzdA==",
            b"MAIL FROM:<anne@example.com>",
            b"RCPT TO:<bob@example.com>",
            b"STARTTLS",
        )
        # Full re-negotiation over TLS.
        d.send(
            b"EHLO secure.example",
            b"AUTH PLAIN AHRlc3QAdGVzdA==",
            b"MAIL FROM:<carol@example.com>",
            b"RCPT TO:<dave@example.com>",
            b"RCPT TO:<erin@example.com>",
            b"DATA",
            b"hello over tls",
            b".",
        )
        assert len(d.handler.box) == 1
        delivery = d.handler.box[0]
        # The handler sees only the post-TLS envelope, never the cleartext one.
        assert delivery.envelope.mail_from == "carol@example.com"
        assert delivery.envelope.rcpt_tos == ["dave@example.com", "erin@example.com"]
        assert delivery.envelope.content == b"hello over tls\r\n"
        assert delivery.session.authenticated is True
        assert delivery.session.host_name == "secure.example"
        assert delivery.session.ssl is not None


# endregion


# region #### Failed / cancelled handshakes ##########################################


class TestHandshakeFailure:
    def test_failed_handshake_closes_connection_and_rejects_data(self, driver):
        d = driver(HANDSHAKE_FAIL)
        d.send(
            b"EHLO plain.example",
            b"MAIL FROM:<anne@example.com>",
            b"RCPT TO:<bob@example.com>",
        )
        d.send(b"STARTTLS")
        # The handshake error is surfaced through handle_exception.
        assert any(
            isinstance(exc, TLSSetupException) for exc in d.handler.exceptions
        )
        assert d.transport.closed is True
        assert d.server.transport is None

        # Any further command (DATA included) cannot be accepted: the server
        # has torn the connection down.
        responses = d.send(b"DATA")
        assert responses == []
        assert d.handler.box == []

    def test_cancelled_handshake_does_not_accept_data(self, driver):
        d = driver(HANDSHAKE_CANCEL)
        d.send(
            b"EHLO plain.example",
            b"MAIL FROM:<anne@example.com>",
            b"RCPT TO:<bob@example.com>",
        )
        d.send(b"STARTTLS")
        # A cancelled waiter aborts smtp_STARTTLS before the app-level
        # connection_made() can run, so no TLS session is recorded.
        assert d.server.session.ssl is None
        responses = d.send(b"DATA", b"MAIL FROM:<x@example.com>")
        # The handler coroutine never resumes past the cancelled handshake, so
        # DATA cannot produce the 354 "go ahead" prompt nor reach the handler.
        assert all(_status(line)[0] != 354 for line in responses)
        assert d.handler.box == []

    def test_hook_rejection_refuses_every_command_but_quit(self, driver):
        d = driver(starttls_result=False)
        d.send(
            b"EHLO plain.example",
            b"MAIL FROM:<anne@example.com>",
            b"RCPT TO:<bob@example.com>",
            b"STARTTLS",
        )
        assert d.server._tls_handshake_okay is False
        # The handshake still rebuilt state (fresh envelope), even though the
        # handler then refused the secured session.
        assert d.server.envelope.rcpt_tos == []

        data_resp = d.send(b"DATA")
        assert _status(data_resp[-1]) == (554, S.S554_LACK_SECURITY.mesg)
        mail_resp = d.send(b"MAIL FROM:<x@example.com>")
        assert _status(mail_resp[-1]) == (554, S.S554_LACK_SECURITY.mesg)
        rcpt_resp = d.send(b"RCPT TO:<y@example.com>")
        assert _status(rcpt_resp[-1]) == (554, S.S554_LACK_SECURITY.mesg)
        assert d.handler.box == []

        quit_resp = d.send(b"QUIT")
        assert _status(quit_resp[-1]) == (221, b"Bye")


# endregion


# region #### Repeated STARTTLS ######################################################


class TestRepeatedStartTLS:
    def test_second_starttls_after_re_ehlo_is_refused(self, driver):
        d = driver()
        d.send(b"EHLO plain.example", b"STARTTLS", b"EHLO secure.example")
        responses = d.send(b"STARTTLS")
        # RFC 3207 section 4: a second STARTTLS must get 503, not another 220.
        assert _status(responses[-1]) == (503, S.S503_STARTTLS_ACTIVE.mesg)

    def test_second_starttls_does_not_rebuild_transport(self, driver):
        d = driver()
        d.send(b"EHLO plain.example", b"STARTTLS", b"EHLO secure.example")
        tls_protocol = d.server._tls_protocol
        transport = d.server.transport
        d.send(b"STARTTLS")
        assert d.server._tls_protocol is tls_protocol
        assert d.server.transport is transport


# endregion
