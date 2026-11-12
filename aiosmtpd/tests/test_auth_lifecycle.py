# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
Lifecycle tests for custom multi-round AUTH mechanisms.

These tests run the SMTP protocol against an in-memory, pausable stream so that
success, per-round cancellation, malformed Base64, handler errors and mid-AUTH
disconnects can all be exercised without binding a real socket.
"""

import asyncio
import logging
from base64 import b64encode
from contextlib import suppress
from typing import List, Optional
from unittest.mock import Mock

import pytest

from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import (
    SMTP as Server,
    AuthInteractResult,
    AuthInteractStatus,
    AuthResult,
    LoginPassword,
    MISSING,
)
from aiosmtpd.testing.statuscodes import SMTP_STATUS_CODES as S


SECRET_USER = b"twouser"
SECRET_PASS = b"twopass"
SECRET_TOKEN = b"round-two-token"
CHALLENGE_ONE = "round-one"
CHALLENGE_TWO = "round-two"


def b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


class PausableMemoryStream:
    """
    In-memory client stream. Feed data is buffered until ``resume()`` is called,
    allowing a test to prove the server is parked on a challenge while the
    stream is paused.
    """

    def __init__(self, protocol: Server):
        self.protocol = protocol
        self.paused = False
        self.pending = bytearray()

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False
        if self.pending:
            buffered = bytes(self.pending)
            self.pending.clear()
            self.protocol.data_received(buffered)

    def send(self, raw: bytes) -> None:
        if self.paused:
            self.pending.extend(raw)
        else:
            self.protocol.data_received(raw)

    def send_line(self, line: str) -> None:
        self.send(line.encode("ascii") + b"\r\n")

    def disconnect(self) -> None:
        # Simulate a clean TCP FIN: the reader reaches EOF and any readline()
        # parked on a challenge returns b"".
        self.resume()
        self.protocol._reader.feed_eof()


class TwoRoundAuthHandler(Sink):
    """
    A two-round test mechanism using the structured auth_challenge() API.

    Round 1 gathers the username, round 2 the password. Every interaction
    result is recorded so tests can assert the distinguishable outcomes.
    """

    mechanism_name = "TWOROUND"

    def __init__(self):
        self.interactions: List[AuthInteractResult] = []
        self.temp_state: dict = {}
        self.authenticator_calls = 0

    def authenticator(self, server, session, envelope, mechanism, auth_data):
        self.authenticator_calls += 1
        assert mechanism == self.mechanism_name
        assert isinstance(auth_data, LoginPassword)
        if auth_data == LoginPassword(SECRET_USER, SECRET_PASS):
            return AuthResult(success=True, auth_data=auth_data)
        return AuthResult(success=False, handled=False)

    async def auth_TWOROUND(self, server: Server, args: List[str]):
        first = await server.auth_challenge(CHALLENGE_ONE)
        self.interactions.append(first)
        if not first.success:
            return AuthResult(success=False, handled=True)
        # Temporary, round-one state must be released if round 2 fails.
        self.temp_state["user"] = first.response
        second = await server.auth_challenge(CHALLENGE_TWO)
        self.interactions.append(second)
        if not second.success:
            self.temp_state.clear()
            return AuthResult(success=False, handled=True)
        auth_data = LoginPassword(first.response, second.response)
        result = server._authenticate(self.mechanism_name, auth_data)
        if not result.success:
            self.temp_state.clear()
        return result


class RaisingAuthHandler(Sink):
    """A mechanism that raises after the first successful round."""

    def __init__(self):
        self.interactions: List[AuthInteractResult] = []

    async def auth_BROKEN(self, server: Server, args: List[str]):
        first = await server.auth_challenge(CHALLENGE_ONE)
        self.interactions.append(first)
        if not first.success:
            return AuthResult(success=False, handled=True)
        raise RuntimeError("boom from auth handler")


class LegacyPlainHandler(Sink):
    """Exercises the legacy challenge_auth() -> MISSING/bytes contract."""

    def __init__(self):
        self.results: List[object] = []

    async def auth_LEGACY(self, server: Server, args: List[str]):
        response = await server.challenge_auth("legacy")
        self.results.append(response)
        if response is MISSING:
            return AuthResult(success=False, handled=True)
        return AuthResult(success=True, auth_data=response)


@pytest.fixture
def auth_protocol(temp_event_loop):
    responses: List[bytes] = []
    transport = Mock()
    transport.write = responses.append
    transport.get_extra_info.return_value = ("127.0.0.1", 4321)
    transport.is_closing.return_value = False

    handler = TwoRoundAuthHandler()
    protocol = Server(
        handler,
        loop=temp_event_loop,
        decode_data=True,
        enable_SMTPUTF8=True,
        auth_require_tls=False,
        authenticator=handler.authenticator,
    )
    protocol.connection_made(transport)
    stream = PausableMemoryStream(protocol)
    yield handler, protocol, stream, responses
    _shutdown_protocol(protocol, temp_event_loop)


def _run_until_idle(loop: asyncio.AbstractEventLoop) -> None:
    async def _idle():
        # Two loop iterations let push() drains and follow-up reads settle.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    loop.run_until_complete(_idle())


def _shutdown_protocol(protocol: Server, loop: asyncio.AbstractEventLoop) -> None:
    """Drain the handler task to completion, cancelling it if still parked."""
    task = protocol._handler_coroutine
    assert task is not None
    if not task.done():
        task.cancel()

    async def _drain():
        with suppress(asyncio.CancelledError):
            await task

    loop.run_until_complete(_drain())
    assert task.done()


def _ehlo(stream: PausableMemoryStream, loop: asyncio.AbstractEventLoop) -> None:
    stream.send_line("EHLO example.com")
    _run_until_idle(loop)


def _start_mechanism(stream: PausableMemoryStream, loop, name: str) -> None:
    stream.send_line(f"AUTH {name}")
    _run_until_idle(loop)


def _joined(responses: List[bytes]) -> bytes:
    return b"".join(responses)


class TestAuthLifecycle:
    def test_success_two_rounds_pausable(self, auth_protocol, temp_event_loop):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        # Pause before answering; the server must stay parked on round one.
        stream.pause()
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        assert b"334 " + b64encode(CHALLENGE_ONE.encode()) in _joined(responses)
        assert b"334 " + b64encode(CHALLENGE_TWO.encode()) not in _joined(responses)
        assert handler.interactions == []
        # Resume: buffered round-one answer is delivered, then round two.
        stream.resume()
        stream.send_line(b64(SECRET_PASS))
        _run_until_idle(temp_event_loop)

        assert [r.status for r in handler.interactions] == [
            AuthInteractStatus.OK,
            AuthInteractStatus.OK,
        ]
        assert handler.interactions[0].response == SECRET_USER
        assert handler.interactions[1].response == SECRET_PASS
        assert handler.authenticator_calls == 1
        assert protocol.session.authenticated is True
        assert protocol.session.auth_data == LoginPassword(SECRET_USER, SECRET_PASS)
        assert S.S235_AUTH_SUCCESS.to_bytes() in _joined(responses)
        assert not protocol._auth_in_progress

        # Next ordinary command is interpreted normally.
        stream.send_line("NOOP")
        _run_until_idle(temp_event_loop)
        assert _joined(responses).endswith(S.S250_OK.to_bytes() + b"\r\n")

    def test_cancel_round_one(self, auth_protocol, temp_event_loop):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        stream.send_line("*")
        _run_until_idle(temp_event_loop)

        assert len(handler.interactions) == 1
        assert handler.interactions[0].status is AuthInteractStatus.CANCELLED
        assert handler.interactions[0].response is None
        assert handler.authenticator_calls == 0
        assert S.S501_AUTH_ABORTED.to_bytes() in _joined(responses)
        self._assert_clean_session(protocol, handler)
        self._assert_next_command_normal(stream, temp_event_loop, responses)
        # A subsequent EHLO is handled as an ordinary command and still offers
        # the (never-authenticated) mechanism again.
        before = len(_joined(responses))
        stream.send_line("EHLO example.com")
        _run_until_idle(temp_event_loop)
        ehlo_reply = _joined(responses)[before:]
        assert ehlo_reply.startswith(b"250-")
        assert b"250-AUTH" in ehlo_reply
        assert b"TWOROUND" in ehlo_reply

    def test_cancel_round_two(self, auth_protocol, temp_event_loop):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        stream.send_line("*")
        _run_until_idle(temp_event_loop)

        assert [r.status for r in handler.interactions] == [
            AuthInteractStatus.OK,
            AuthInteractStatus.CANCELLED,
        ]
        assert handler.interactions[1].response is None
        assert handler.authenticator_calls == 0
        assert S.S501_AUTH_ABORTED.to_bytes() in _joined(responses)
        self._assert_clean_session(protocol, handler)
        self._assert_next_command_normal(stream, temp_event_loop, responses)

    def test_bad_base64_round_one(self, auth_protocol, temp_event_loop, caplog):
        handler, protocol, stream, responses = auth_protocol
        caplog.set_level(logging.DEBUG)
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        bad_blob = "not@base64!"
        stream.send_line(bad_blob)
        _run_until_idle(temp_event_loop)

        assert len(handler.interactions) == 1
        assert handler.interactions[0].status is AuthInteractStatus.BAD_RESPONSE
        assert handler.interactions[0].response is None
        assert handler.authenticator_calls == 0
        assert S.S501_AUTH_NOTB64.to_bytes() in _joined(responses)
        self._assert_clean_session(protocol, handler)
        # Failure diagnostics must not echo the raw credential blob, but the
        # failure itself must still be recorded.
        assert bad_blob not in caplog.text
        assert "undecodable Base64" in caplog.text
        self._assert_next_command_normal(stream, temp_event_loop, responses)

    def test_bad_base64_round_two(self, auth_protocol, temp_event_loop):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        stream.send_line("@@bad@@")
        _run_until_idle(temp_event_loop)

        assert [r.status for r in handler.interactions] == [
            AuthInteractStatus.OK,
            AuthInteractStatus.BAD_RESPONSE,
        ]
        assert handler.authenticator_calls == 0
        assert S.S501_AUTH_NOTB64.to_bytes() in _joined(responses)
        self._assert_clean_session(protocol, handler)
        self._assert_next_command_normal(stream, temp_event_loop, responses)

    def test_handler_exception_does_not_swallow_next_command(
        self, auth_protocol, temp_event_loop
    ):
        _, protocol, stream, responses = auth_protocol
        # Swap in the raising handler/mechanism on the same protocol instance.
        raising = RaisingAuthHandler()
        protocol.event_handler = raising
        protocol._auth_methods["BROKEN"] = type(
            protocol._auth_methods["TWOROUND"]
        )(raising.auth_BROKEN, False)

        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "BROKEN")
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)

        assert len(raising.interactions) == 1
        assert raising.interactions[0].status is AuthInteractStatus.OK
        # Exception surfaced as a 500, exchange fully torn down.
        assert _joined(responses).split(b"\r\n")[-2].startswith(b"500 ")
        self._assert_clean_session(protocol, None)
        self._assert_next_command_normal(stream, temp_event_loop, responses)

    def test_disconnect_during_challenge(self, auth_protocol, temp_event_loop):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        # Park the mechanism on round one, then drop the connection.
        task = protocol._handler_coroutine
        assert task is not None
        stream.disconnect()
        with suppress(asyncio.CancelledError):
            temp_event_loop.run_until_complete(
                asyncio.wait_for(asyncio.shield(task), timeout=5)
            )

        assert len(handler.interactions) == 1
        assert (
            handler.interactions[0].status
            is AuthInteractStatus.CONNECTION_LOST
        )
        assert handler.interactions[0].response is None
        assert handler.authenticator_calls == 0
        assert not protocol._auth_in_progress
        assert protocol.session.authenticated is None
        assert protocol.session.auth_data is None
        assert handler.temp_state == {}
        assert task.done()

    def test_retry_after_failure_is_fresh_attempt(
        self, auth_protocol, temp_event_loop
    ):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        # Fail an attempt first.
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        stream.send_line("*")
        _run_until_idle(temp_event_loop)
        assert handler.authenticator_calls == 0
        # A new AUTH must start from round one again and succeed.
        _start_mechanism(stream, temp_event_loop, "TWOROUND")
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        stream.send_line(b64(SECRET_PASS))
        _run_until_idle(temp_event_loop)
        assert handler.authenticator_calls == 1
        assert protocol.session.authenticated is True
        assert S.S235_AUTH_SUCCESS.to_bytes() in _joined(responses)

    def test_eof_while_waiting_for_command_stops_cleanly(
        self, auth_protocol, temp_event_loop
    ):
        handler, protocol, stream, responses = auth_protocol
        _ehlo(stream, temp_event_loop)
        task = protocol._handler_coroutine
        assert task is not None
        # Close the connection while the command loop (not a challenge) waits.
        stream.disconnect()
        with suppress(asyncio.CancelledError):
            temp_event_loop.run_until_complete(
                asyncio.wait_for(asyncio.shield(task), timeout=5)
            )
        # The loop returns instead of spinning; no AUTH ever started.
        assert task.done()
        assert handler.interactions == []
        assert handler.authenticator_calls == 0
        assert protocol.session.authenticated is None

    @staticmethod
    def _assert_clean_session(protocol: Server, handler: Optional[TwoRoundAuthHandler]):
        assert not protocol._auth_in_progress
        assert protocol.session.authenticated is None
        assert protocol.session.auth_data is None
        if handler is not None:
            assert handler.temp_state == {}

    @staticmethod
    def _assert_next_command_normal(
        stream: PausableMemoryStream,
        loop: asyncio.AbstractEventLoop,
        responses: List[bytes],
    ):
        before = len(_joined(responses))
        stream.send_line("NOOP")
        _run_until_idle(loop)
        sent = _joined(responses)[before:]
        assert sent == S.S250_OK.to_bytes() + b"\r\n"


class TestLegacyChallengeContract:
    @pytest.fixture
    def legacy_protocol(self, temp_event_loop):
        responses: List[bytes] = []
        transport = Mock()
        transport.write = responses.append
        transport.get_extra_info.return_value = ("127.0.0.1", 4322)
        transport.is_closing.return_value = False

        handler = LegacyPlainHandler()
        protocol = Server(
            handler,
            loop=temp_event_loop,
            decode_data=True,
            auth_require_tls=False,
        )
        protocol.connection_made(transport)
        stream = PausableMemoryStream(protocol)
        yield handler, protocol, stream, responses
        _shutdown_protocol(protocol, temp_event_loop)

    def test_missing_on_abort_and_bad_base64(self, legacy_protocol, temp_event_loop):
        handler, protocol, stream, responses = legacy_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "LEGACY")
        stream.send_line("*")
        _run_until_idle(temp_event_loop)
        assert handler.results == [MISSING]
        assert protocol.session.authenticated is None
        # A fresh attempt with valid data succeeds via the legacy contract.
        _start_mechanism(stream, temp_event_loop, "LEGACY")
        stream.send_line(b64(SECRET_TOKEN))
        _run_until_idle(temp_event_loop)
        assert handler.results[1] == SECRET_TOKEN
        assert protocol.session.authenticated is True


class TestTlsAndCapabilityConsistency:
    @pytest.fixture
    def make_protocol(self, temp_event_loop):
        loop = temp_event_loop
        created: List[Server] = []

        def _make(**kwargs):
            responses: List[bytes] = []
            transport = Mock()
            transport.write = responses.append
            transport.get_extra_info.return_value = ("127.0.0.1", 4323)
            transport.is_closing.return_value = False
            protocol = Server(Sink(), loop=loop, **kwargs)
            protocol.connection_made(transport)
            created.append(protocol)
            return PausableMemoryStream(protocol), protocol, responses

        yield _make
        for protocol in created:
            _shutdown_protocol(protocol, loop)

    def test_auth_hidden_and_refused_without_tls(
        self, make_protocol, temp_event_loop
    ):
        stream, protocol, responses = make_protocol(auth_require_tls=True)
        _ehlo(stream, temp_event_loop)
        ehlo_payload = _joined(responses)
        assert b"AUTH" not in ehlo_payload
        _start_mechanism(stream, temp_event_loop, "PLAIN")
        _run_until_idle(temp_event_loop)
        assert S.S538_AUTH_ENCRYPTREQ.to_bytes() in _joined(responses)
        assert protocol.session.authenticated is None

    def test_capability_matches_allowed_mechanisms(
        self, make_protocol, temp_event_loop
    ):
        stream, protocol, responses = make_protocol(
            auth_require_tls=False,
            auth_exclude_mechanism=["PLAIN"],
        )
        _ehlo(stream, temp_event_loop)
        ehlo_payload = _joined(responses)
        auth_line = next(
            line for line in ehlo_payload.split(b"\r\n") if line.startswith(b"250-AUTH")
        )
        advertised = auth_line.split(b" ", 1)[1].split(b" ")
        assert b"PLAIN" not in advertised
        assert b"LOGIN" in advertised
        # Every advertised mechanism is actually dispatchable, and vice versa.
        assert sorted(m.decode() for m in advertised) == sorted(
            protocol._auth_methods
        )
        _start_mechanism(stream, temp_event_loop, "PLAIN")
        _run_until_idle(temp_event_loop)
        assert S.S504_AUTH_UNRECOG.to_bytes() in _joined(responses)


class TestBuiltinMechanismCompatibility:
    @pytest.fixture
    def login_protocol(self, temp_event_loop):
        responses: List[bytes] = []
        transport = Mock()
        transport.write = responses.append
        transport.get_extra_info.return_value = ("127.0.0.1", 4324)
        transport.is_closing.return_value = False

        def auth_callback(mechanism, login, password):
            auth_callback.calls += 1
            return login == SECRET_USER and password == SECRET_PASS

        auth_callback.calls = 0
        protocol = Server(
            Sink(),
            loop=temp_event_loop,
            decode_data=True,
            auth_require_tls=False,
            auth_callback=auth_callback,
        )
        protocol.connection_made(transport)
        stream = PausableMemoryStream(protocol)
        yield protocol, stream, responses, auth_callback
        _shutdown_protocol(protocol, temp_event_loop)

    def test_login_full_exchange_and_abort_cleanup(
        self, login_protocol, temp_event_loop
    ):
        protocol, stream, responses, callback = login_protocol
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "LOGIN")
        assert S.S334_AUTH_USERNAME.to_bytes() in _joined(responses)
        # Abort at the password prompt; no callback, clean session.
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        assert S.S334_AUTH_PASSWORD.to_bytes() in _joined(responses)
        stream.send_line("*")
        _run_until_idle(temp_event_loop)
        assert callback.calls == 0
        assert protocol.session.authenticated is None
        assert protocol.session.auth_data is None
        assert S.S501_AUTH_ABORTED.to_bytes() in _joined(responses)
        # Retry and complete the LOGIN exchange successfully.
        _start_mechanism(stream, temp_event_loop, "LOGIN")
        stream.send_line(b64(SECRET_USER))
        _run_until_idle(temp_event_loop)
        stream.send_line(b64(SECRET_PASS))
        _run_until_idle(temp_event_loop)
        assert callback.calls == 1
        assert protocol.session.authenticated is True
        assert S.S235_AUTH_SUCCESS.to_bytes() in _joined(responses)

    def test_login_bad_base64_does_not_log_credentials(
        self, login_protocol, temp_event_loop, caplog
    ):
        protocol, stream, responses, callback = login_protocol
        caplog.set_level(logging.DEBUG)
        _ehlo(stream, temp_event_loop)
        _start_mechanism(stream, temp_event_loop, "LOGIN")
        bad = "ab@%"
        stream.send_line(bad)
        _run_until_idle(temp_event_loop)
        assert S.S501_AUTH_NOTB64.to_bytes() in _joined(responses)
        assert bad not in caplog.text
        assert callback.calls == 0
        assert protocol.session.authenticated is None
