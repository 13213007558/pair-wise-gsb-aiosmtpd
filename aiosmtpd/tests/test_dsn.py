# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Test RFC 3461 DSN (Delivery Status Notification) support."""

import asyncio
from asyncio.transports import Transport
from contextlib import suppress
from typing import Callable, List, Set, Tuple, cast

import pytest
from pytest_mock import MockFixture

from aiosmtpd.smtp import (
    MISSING,
    SMTP as Server,
    Envelope,
    RcptInfo,
    Session,
)

BCRLF = b"\r\n"

S250_OK = b"250 OK\r\n"
S221_BYE = b"221 Bye\r\n"
S354 = b"354 End data with <CR><LF>.<CR><LF>\r\n"
S501_MAIL_E = b"501 Syntax: MAIL FROM: <address> [SP <mail-parameters>]\r\n"
S501_RCPT_E = b"501 Syntax: RCPT TO: <address> [SP <mail-parameters>]\r\n"
S555_MAIL = b"555 MAIL FROM parameters not recognized or not implemented\r\n"
S555_RCPT = b"555 RCPT TO parameters not recognized or not implemented\r\n"


class DSNHandler:
    """
    Records envelopes and RCPT hook invocations.  Recipients listed in
    'reject' are refused by the RCPT hook, everything else is accepted
    with the default processing (by returning MISSING).
    """

    def __init__(self) -> None:
        self.box: List[Envelope] = []
        self.rcpt_calls: List[Tuple[str, List[str]]] = []
        self.reject: Set[str] = set()

    async def handle_RCPT(
            self,
            server: Server,
            session: Session,
            envelope: Envelope,
            address: str,
            rcpt_options: List[str],
    ):
        self.rcpt_calls.append((address, list(rcpt_options)))
        if address in self.reject:
            return "550 5.1.1 No such user"
        return MISSING

    async def handle_DATA(
            self, server: Server, session: Session, envelope: Envelope
    ) -> str:
        self.box.append(envelope)
        return "250 OK"


@pytest.fixture
def transport_resp(mocker: MockFixture) -> Tuple[Transport, list]:
    responses = []
    mocked = mocker.Mock()
    mocked.write = responses.append
    #
    return cast(Transport, mocked), responses


@pytest.fixture
def get_protocol(
    temp_event_loop: asyncio.AbstractEventLoop,
    transport_resp: Tuple[Transport, list],
) -> Callable[..., Server]:
    transport, _ = transport_resp

    def getter(*args, **kwargs) -> Server:
        kwargs.setdefault("enable_DSN", True)
        protocol = Server(*args, loop=temp_event_loop, **kwargs)
        protocol.connection_made(transport)
        return protocol

    return getter


def converse(
        protocol: Server,
        temp_event_loop: asyncio.AbstractEventLoop,
        lines: List[bytes],
) -> None:
    """Feed a whole SMTP conversation (one connection) to the protocol."""
    protocol.data_received(BCRLF.join(lines) + BCRLF)
    with suppress(asyncio.CancelledError):
        temp_event_loop.run_until_complete(protocol._handler_coroutine)


def command_replies(responses: list) -> List[bytes]:
    """Filter out the greeting and EHLO multiline responses."""
    result = []
    for resp in responses:
        if resp.startswith((b"220 ", b"250-")) or resp == b"250 HELP\r\n":
            continue
        result.append(resp)
    return result
class TestDSNAdvertisement:
    def test_ehlo_announces_dsn_when_enabled(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        protocol = get_protocol(DSNHandler())
        converse(protocol, temp_event_loop, [b"EHLO example.org", b"QUIT"])
        _, responses = transport_resp
        assert b"250-DSN\r\n" in responses

    def test_ehlo_no_dsn_when_disabled(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        protocol = get_protocol(DSNHandler(), enable_DSN=False)
        converse(protocol, temp_event_loop, [b"EHLO example.org", b"QUIT"])
        _, responses = transport_resp
        assert b"250-DSN\r\n" not in responses

    def test_dsn_params_rejected_when_disabled(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        handler = DSNHandler()
        protocol = get_protocol(handler, enable_DSN=False)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org> ENVID=abc123",
                b"MAIL FROM:<alice@example.org> RET=FULL",
                b"MAIL FROM:<alice@example.org>",
                b"RCPT TO:<bob@example.com> NOTIFY=SUCCESS",
                b"RCPT TO:<bob@example.com> ORCPT=rfc822;bob@example.com",
                b"RCPT TO:<bob@example.com>",
                b"DATA",
                b"Some message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses) == [
            S555_MAIL,
            S555_MAIL,
            S250_OK,
            S555_RCPT,
            S555_RCPT,
            S250_OK,
            S354,
            S250_OK,
            S221_BYE,
        ]
        # The accepted message carries no DSN state at all.
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.envid is None
        assert envelope.dsn_ret is None
        assert envelope.rcpt_tos == ["bob@example.com"]
        assert envelope.rcpt_infos == [RcptInfo("bob@example.com", None, None)]

class TestDSNTwoMessages:
    def test_two_messages_one_connection(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        """Two messages with different DSN params over a single connection.

        First message: one recipient wants failure notifications only, the
        other wants success and delay notifications.  Second message: the
        same recipient address appears twice with different parameters.
        """
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                # First message
                b"MAIL FROM:<alice@example.org> ENVID=msg+2D001 RET=HDRS",
                b"RCPT TO:<bob@example.com> NOTIFY=FAILURE",
                b"RCPT TO:<carol@example.com> NOTIFY=SUCCESS,DELAY"
                b" ORCPT=rfc822;carol+40example.com",
                b"DATA",
                b"First message.",
                b".",
                # Second message, different parameters
                b"MAIL FROM:<dave@example.org> RET=FULL",
                b"RCPT TO:<bob@example.com> NOTIFY=NEVER",
                b"RCPT TO:<bob@example.com> NOTIFY=SUCCESS,FAILURE"
                b" ORCPT=rfc822;bob@example.com",
                b"DATA",
                b"Second message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses) == [
            S250_OK,                # MAIL 1
            S250_OK,                # RCPT bob
            S250_OK,                # RCPT carol
            S354,                   # DATA
            S250_OK,                # end of DATA 1
            S250_OK,                # MAIL 2
            S250_OK,                # RCPT bob (NEVER)
            S250_OK,                # RCPT bob again
            S354,                   # DATA
            S250_OK,                # end of DATA 2
            S221_BYE,               # QUIT
        ]
        assert len(handler.box) == 2
        #
        # First envelope
        env1 = handler.box[0]
        assert env1.mail_from == "alice@example.org"
        # ENVID is xtext-decoded ("+2D" is "-")
        assert env1.envid == "msg-001"
        assert env1.dsn_ret == "HDRS"
        # Legacy attributes still visible to old handlers
        assert env1.mail_options == ["ENVID=MSG+2D001", "RET=HDRS"]
        assert env1.rcpt_tos == ["bob@example.com", "carol@example.com"]
        assert env1.rcpt_options == [
            "NOTIFY=FAILURE",
            "NOTIFY=SUCCESS,DELAY",
            "ORCPT=RFC822;CAROL+40EXAMPLE.COM",
        ]
        # Ordered per-recipient details
        assert env1.rcpt_infos == [
            RcptInfo("bob@example.com", ["FAILURE"], None),
            RcptInfo(
                "carol@example.com",
                ["SUCCESS", "DELAY"],
                "rfc822;carol+40example.com",
            ),
        ]
        #
        # Second envelope: no state leaks from the first message
        env2 = handler.box[1]
        assert env2.mail_from == "dave@example.org"
        assert env2.envid is None
        assert env2.dsn_ret == "FULL"
        # Duplicate recipient address kept twice, in order, each with its
        # own parameters (no dict-by-address collapsing)
        assert env2.rcpt_tos == ["bob@example.com", "bob@example.com"]
        assert env2.rcpt_infos == [
            RcptInfo("bob@example.com", ["NEVER"], None),
            RcptInfo(
                "bob@example.com",
                ["SUCCESS", "FAILURE"],
                "rfc822;bob@example.com",
            ),
        ]

class TestDSNParamErrors:
    def test_notify_never_not_combinable(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        """NOTIFY=NEVER must not appear with any other NOTIFY value."""
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org>",
                b"RCPT TO:<bob@example.com> NOTIFY=NEVER,SUCCESS",
                b"RCPT TO:<bob@example.com> NOTIFY=FAILURE,NEVER",
                b"RCPT TO:<bob@example.com> NOTIFY=NEVER",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses) == [
            S250_OK,
            S501_RCPT_E,
            S501_RCPT_E,
            S250_OK,
            S354,
            S250_OK,
            S221_BYE,
        ]
        # Only the valid RCPT made it into the envelope
        envelope = handler.box[0]
        assert envelope.rcpt_tos == ["bob@example.com"]
        assert envelope.rcpt_infos == [
            RcptInfo("bob@example.com", ["NEVER"], None),
        ]

    @pytest.mark.parametrize("mail_command", [
        b"MAIL FROM:<a@example.org> ENVID=bad+2",      # incomplete hexpair
        b"MAIL FROM:<a@example.org> ENVID=bad+2G",     # invalid hex digit
        b"MAIL FROM:<a@example.org> ENVID=bad=xx",     # '=' not xtext
        b"MAIL FROM:<a@example.org> ENVID=bad+2f+2",   # trailing junk
        b"MAIL FROM:<a@example.org> ENVID=",           # empty value
        b"MAIL FROM:<a@example.org> ENVID=x" + b"y" * 100,  # too long
        b"MAIL FROM:<a@example.org> RET",              # RET needs a value
        b"MAIL FROM:<a@example.org> RET=FULLS",        # invalid RET value
        b"MAIL FROM:<a@example.org> @@=x",             # invalid param name
    ])
    def test_invalid_mail_params(
            self, temp_event_loop, transport_resp, get_protocol, mail_command
    ):
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                mail_command,
                b"RCPT TO:<bob@example.com>",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        replies = command_replies(responses)
        assert replies[0] == S501_MAIL_E
        # Failed MAIL leaves no state, so RCPT is rejected with 503
        assert replies[1] == b"503 Error: need MAIL command\r\n"
        assert handler.box == []
    @pytest.mark.parametrize("rcpt_params", [
        b"ORCPT=rfc822;bad+4",          # incomplete hexpair
        b"ORCPT=rfc822;bad+4Z",         # invalid hex digit
        b"ORCPT=rfc822;bad=4",          # '=' not xtext
        b"ORCPT=no-addr-type",          # missing ';'
        b"ORCPT=;foo@example.com",      # empty addr-type
        b"ORCPT=rfc822;",               # empty xtext
        b"ORCPT=",                      # empty value
        b"ORCPT",                       # ORCPT needs a value
        b"NOTIFY=MAYBE",                # unknown notify value
        b"NOTIFY=",                     # empty value
        b"NOTIFY",                      # NOTIFY needs a value
    ])
    def test_invalid_rcpt_params(
            self, temp_event_loop, transport_resp, get_protocol, rcpt_params
    ):
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org>",
                b"RCPT TO:<bob@example.com> " + rcpt_params,
                b"RCPT TO:<carol@example.com>",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        replies = command_replies(responses)
        assert replies[:3] == [S250_OK, S501_RCPT_E, S250_OK]
        # The rejected RCPT leaves no partial state behind: only the
        # valid recipient shows up in the envelope.
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.rcpt_tos == ["carol@example.com"]
        assert envelope.rcpt_options == []
        assert envelope.rcpt_infos == [RcptInfo("carol@example.com", None, None)]

    @pytest.mark.parametrize("command", [
        b"MAIL FROM:<a@example.org> ENVID=x ENVID=y",
        b"MAIL FROM:<a@example.org> RET=FULL RET=HDRS",
        b"MAIL FROM:<a@example.org> SIZE=10 SIZE=20",
        b"MAIL FROM:<a@example.org> ENVID=x envid=y",
    ])
    def test_duplicate_mail_params(
            self, temp_event_loop, transport_resp, get_protocol, command
    ):
        protocol = get_protocol(DSNHandler())
        converse(
            protocol,
            temp_event_loop,
            [b"EHLO example.org", command, b"QUIT"],
        )
        _, responses = transport_resp
        assert command_replies(responses)[0] == S501_MAIL_E

    @pytest.mark.parametrize("rcpt_params", [
        b"NOTIFY=SUCCESS NOTIFY=FAILURE",
        b"NOTIFY=SUCCESS notify=failure",
        b"ORCPT=rfc822;a@b ORCPT=rfc822;a@b",
    ])
    def test_duplicate_rcpt_params(
            self, temp_event_loop, transport_resp, get_protocol, rcpt_params
    ):
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org>",
                b"RCPT TO:<bob@example.com> " + rcpt_params,
                b"DATA",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        replies = command_replies(responses)
        assert replies[:2] == [S250_OK, S501_RCPT_E]
        # No recipient state at all: DATA is rejected with 503
        assert replies[2] == b"503 Error: need RCPT command\r\n"
        assert handler.box == []

    @pytest.mark.parametrize("command,expected", [
        (b"MAIL FROM:<a@example.org> FOO=bar", S555_MAIL),
        (b"MAIL FROM:<a@example.org> FOO", S555_MAIL),
    ])
    def test_unknown_mail_params(
            self, temp_event_loop, transport_resp, get_protocol,
            command, expected,
    ):
        protocol = get_protocol(DSNHandler())
        converse(
            protocol,
            temp_event_loop,
            [b"EHLO example.org", command, b"QUIT"],
        )
        _, responses = transport_resp
        assert command_replies(responses)[0] == expected

    def test_unknown_rcpt_params(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        protocol = get_protocol(DSNHandler())
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org>",
                b"RCPT TO:<bob@example.com> FOO=bar",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses)[1] == S555_RCPT

    def test_keywords_case_insensitive_values_preserved(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        """Parameter keywords and token values are case-insensitive, but
        xtext values (ENVID, ORCPT) keep their original case."""
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"mail from:<alice@example.org> envid=Msg+2D001 ret=full",
                b"rcpt to:<Bob@example.com> notify=success,delay"
                b" orcpt=rfc822;Bob@example.com",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses)[:3] == [S250_OK, S250_OK, S354]
        envelope = handler.box[0]
        assert envelope.envid == "Msg-001"
        assert envelope.dsn_ret == "FULL"
        assert envelope.rcpt_infos == [
            RcptInfo(
                "Bob@example.com",
                ["SUCCESS", "DELAY"],
                "rfc822;Bob@example.com",
            ),
        ]

class TestDSNStateReset:
    def test_rset_clears_dsn_state(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        handler = DSNHandler()
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org> ENVID=will+2Dvanish RET=FULL",
                b"RCPT TO:<bob@example.com> NOTIFY=SUCCESS ORCPT=rfc822;bob",
                b"RSET",
                b"MAIL FROM:<carol@example.org>",
                b"RCPT TO:<dave@example.com>",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses) == [
            S250_OK, S250_OK, S250_OK, S250_OK, S250_OK, S354, S250_OK,
            S221_BYE,
        ]
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.mail_from == "carol@example.org"
        assert envelope.envid is None
        assert envelope.dsn_ret is None
        assert envelope.mail_options == []
        assert envelope.rcpt_tos == ["dave@example.com"]
        assert envelope.rcpt_options == []
        assert envelope.rcpt_infos == [RcptInfo("dave@example.com", None, None)]

    def test_starttls_clears_dsn_state(
            self, temp_event_loop, transport_resp, get_protocol, mocker
    ):
        """A successful STARTTLS resets the session (RFC 3207 § 4.2), so no
        DSN parameters from before STARTTLS may linger."""
        handler = DSNHandler()
        protocol = get_protocol(handler)
        protocol.data_received(
            b"EHLO example.org\r\n"
            b"MAIL FROM:<alice@example.org> ENVID=secret RET=FULL\r\n"
            b"RCPT TO:<bob@example.com> NOTIFY=SUCCESS\r\n"
        )
        temp_event_loop.run_until_complete(asyncio.sleep(0.1))
        assert protocol.envelope is not None
        assert protocol.envelope.envid == "secret"
        # Simulate completion of the TLS handshake: SMTP.connection_made()
        # is called again with the TLS transport (see smtp_STARTTLS).
        protocol._original_transport = protocol.transport
        protocol._tls_protocol = mocker.Mock()
        protocol._tls_protocol._extra = {"cipher": ("AES", "TLSv1.3", 256)}
        protocol.connection_made(mocker.Mock())
        # All pre-STARTTLS envelope state is gone
        assert protocol.envelope is not None
        assert protocol.envelope.envid is None
        assert protocol.envelope.dsn_ret is None
        assert protocol.envelope.rcpt_infos == []
        # And the post-STARTTLS transaction starts from a clean slate
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<carol@example.org>",
                b"RCPT TO:<dave@example.com>",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.envid is None
        assert envelope.dsn_ret is None
        assert envelope.rcpt_infos == [RcptInfo("dave@example.com", None, None)]


class TestDSNRcptRejection:
    def test_rejected_rcpt_not_in_envelope(
            self, temp_event_loop, transport_resp, get_protocol
    ):
        """Recipients refused by the RCPT hook must not appear in the final
        recipient lists, even if they carried valid DSN parameters."""
        handler = DSNHandler()
        handler.reject.add("carol@example.com")
        protocol = get_protocol(handler)
        converse(
            protocol,
            temp_event_loop,
            [
                b"EHLO example.org",
                b"MAIL FROM:<alice@example.org> ENVID=msg1",
                b"RCPT TO:<bob@example.com> NOTIFY=FAILURE",
                b"RCPT TO:<carol@example.com> NOTIFY=SUCCESS",
                b"RCPT TO:<bob@example.com> NOTIFY=SUCCESS,DELAY",
                b"DATA",
                b"Message.",
                b".",
                b"QUIT",
            ],
        )
        _, responses = transport_resp
        assert command_replies(responses) == [
            S250_OK,
            S250_OK,
            b"550 5.1.1 No such user\r\n",
            S250_OK,
            S354,
            S250_OK,
            S221_BYE,
        ]
        # The RCPT hook saw all three attempts ...
        assert handler.rcpt_calls == [
            ("bob@example.com", ["NOTIFY=FAILURE"]),
            ("carol@example.com", ["NOTIFY=SUCCESS"]),
            ("bob@example.com", ["NOTIFY=SUCCESS,DELAY"]),
        ]
        # ... but only the accepted recipients made it into the envelope
        assert len(handler.box) == 1
        envelope = handler.box[0]
        assert envelope.rcpt_tos == ["bob@example.com", "bob@example.com"]
        assert envelope.rcpt_infos == [
            RcptInfo("bob@example.com", ["FAILURE"], None),
            RcptInfo("bob@example.com", ["SUCCESS", "DELAY"], None),
        ]
