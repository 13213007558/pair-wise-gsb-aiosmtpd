# Copyright 2024 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
DATA end-of-mail marker handling (RFC 5321 s 4.5.2).

The end of the DATA phase is, and must remain, the exact four-octet sequence
``<CR><LF>.<CR><LF>``.  A bare-LF or bare-CR line ending, a dot on a line that
does not end in CRLF, and arbitrary TCP segmentation of that sequence must all
be treated as ordinary message content.  If any of those were accepted as a
terminator, bytes belonging to one mail could be re-interpreted as SMTP
commands of a second, attacker-controlled mail ("SMTP smuggling").

These tests drive the protocol directly over an in-memory transport instead of
a real socket, so every input byte and every response octet is observable and
no network port has to be bound.
"""

import asyncio
import contextlib
import typing as _t

import pytest

from aiosmtpd.lmtp import LMTP
from aiosmtpd.smtp import SMTP


# Short, explicit timeouts so a regression that leaves the server waiting
# inside DATA fails fast instead of hanging the whole test session.
WAIT_TIMEOUT = 2.0


class MemoryTransport(asyncio.Transport):
    """Transport that keeps both directions inside the test process."""

    def __init__(
        self,
        protocol: asyncio.Protocol,
        loop: asyncio.AbstractEventLoop,
        peer: _t.Tuple[str, int] = ("memory", 12525),
    ) -> None:
        super().__init__()
        self._protocol = protocol
        self._peer = peer
        self._closing = False
        self.received = bytearray()

    def write(self, data: bytes) -> None:
        self.received.extend(data)

    def feed(self, data: bytes) -> None:
        self._protocol.data_received(data)

    def feed_eof(self) -> None:
        self._protocol.eof_received()
        self._protocol.connection_lost(None)

    def close(self) -> None:
        if not self._closing:
            self._closing = True
            self._protocol.connection_lost(None)

    def abort(self) -> None:
        self.close()

    def is_closing(self) -> bool:
        return self._closing

    def get_extra_info(self, name: str, default: _t.Any = None) -> _t.Any:
        if name == "peername":
            return self._peer
        return default


class RecordingHandler:
    """Records every completed transaction in delivery order."""

    def __init__(self) -> None:
        self.box: _t.List[bytes] = []
        self.envelopes: _t.List[_t.Any] = []

    async def handle_DATA(
        self,
        server: SMTP,
        session: _t.Any,
        envelope: _t.Any,
    ) -> str:
        self.box.append(envelope.original_content)
        self.envelopes.append(envelope)
        return "250 OK"


class InMemorySMTP:
    """Runs an SMTP protocol instance on a loopback, in-memory connection."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        protocol_factory: _t.Callable[..., asyncio.Protocol] = SMTP,
        greeting: bytes = b"EHLO example.com\r\n",
    ) -> None:
        self.loop = loop
        self.greeting = greeting
        self.handler = RecordingHandler()
        self.protocol = protocol_factory(
            self.handler, loop=loop, timeout=WAIT_TIMEOUT
        )
        self.transport = MemoryTransport(self.protocol, loop)
        self.protocol.connection_made(self.transport)

    async def settle(self) -> None:
        # Let every scheduled protocol callback make progress.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    async def send_chunks(self, chunks: _t.Iterable[bytes]) -> None:
        for chunk in chunks:
            self.transport.feed(chunk)
            await self.settle()

    async def greet(self) -> None:
        await self.send_chunks(
            [
                self.greeting,
                b"MAIL FROM:<anne@example.com>\r\n",
                b"RCPT TO:<bart@example.com>\r\n",
            ]
        )

    async def start_data(self) -> None:
        await self.send_chunks([b"DATA\r\n"])

    def responses(self) -> _t.List[bytes]:
        return [line for line in bytes(self.transport.received).split(b"\r\n")
                if line]

    def reply_codes(self) -> _t.List[int]:
        # A multi-line reply uses "NNN-" continuations and a final "NNN SP";
        # count one code per reply so EHLO's capability list counts once.
        codes: _t.List[int] = []
        for line in self.responses():
            if len(line) < 4 or not line[:3].isdigit():
                continue
            if line[3:4] == b" ":
                codes.append(int(line[:3]))
        return codes

    def last_reply_code(self) -> _t.Optional[int]:
        codes = self.reply_codes()
        return codes[-1] if codes else None

    def close(self) -> None:
        if not self.transport.is_closing():
            self.transport.feed_eof()


# The byte corpus.  Every payload is fed to the server one byte at a time so
# that TCP-style segmentation cannot hide a terminator on a read boundary.

# (id, body sent inside DATA, exact original_content the handler must observe)
CORPUS: _t.List[_t.Tuple[str, bytes, bytes]] = [
    # Minimal legal mail: header + body, terminated by the canonical sequence.
    (
        "canonical_crlf_terminator",
        b"Subject: hello\r\n\r\nbody\r\n.\r\n",
        b"Subject: hello\r\n\r\nbody\r\n",
    ),
    # Transparency: a leading dot on a content line is doubled on the wire and
    # the server must strip exactly one dot before delivery.
    (
        "transparent_dot_unquoted",
        b"Subject: dots\r\n\r\n..kept\r\n.end\r\n.\r\n",
        b"Subject: dots\r\n\r\n.kept\r\nend\r\n",
    ),
    # Bare LF before a lone-dot line.  RFC 5321 only ends DATA on CRLF, so the
    # fake terminator "\n.\r\n" stays inside the mail.
    (
        "bare_lf_fake_terminator",
        b"line one\n.\r\ninjected command\r\n.\r\n",
        b"line one\n.\r\ninjected command\r\n",
    ),
    # Bare CR (no following LF) is content too, including a CR dot CRLF shape.
    (
        "bare_cr_fake_terminator",
        b"line one\r.\r\nstill body\r\n.\r\n",
        b"line one\r.\r\nstill body\r\n",
    ),
    # A dot immediately followed by a bare LF: readuntil(b"\r\n") only returns
    # at the next CRLF, so the first complete line is ".\nstill body\r\n" -- not
    # the terminator-sized b".\r\n".  The leading dot is then de-transparenced,
    # which is why the delivered line starts with "\nstill body".  Either way
    # DATA does not end early.
    (
        "dot_bare_lf_not_terminator",
        b"line one\r\n.\nstill body\r\n.\r\n",
        b"line one\r\n\nstill body\r\n",
    ),
    # Mixed line endings in one body, none of which may end DATA early.
    (
        "mixed_line_endings",
        b"a\r\nb\nc\rd\n.\r\ne\r\n.\r\n",
        b"a\r\nb\nc\rd\n.\r\ne\r\n",
    ),
    # Transparency: content lines that merely *start* with a dot but carry
    # more data never terminate DATA, and have exactly one leading dot removed.
    (
        "dot_content_line_de_transparenced",
        b"..leading dot\r\n.dotx\r\nplain\r\n.\r\n",
        b".leading dot\r\ndotx\r\nplain\r\n",
    ),
    # A bare terminator-shaped sequence inside a longer line is content, e.g.
    # a dot followed by text before the CRLF.
    (
        "dot_with_trailing_text_is_content",
        b".x\r\nplain\r\n.\r\n",
        b"x\r\nplain\r\n",
    ),
    # Empty body: the terminator immediately follows the 354 prompt.
    (
        "empty_body",
        b".\r\n",
        b"",
    ),
]


@pytest.mark.parametrize("case_id,wire_body,expected_content", CORPUS,
                         ids=[item[0] for item in CORPUS])
def test_data_corpus_strict_terminator(
    case_id: str, wire_body: bytes, expected_content: bytes
) -> None:
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.greet()
            await server.start_data()
            # One byte per feed(): worst case for segmentation assumptions.
            await server.send_chunks(bytes([octet]) for octet in wire_body)

            assert len(server.handler.box) == 1, (
                f"{case_id}: expected exactly one transaction, "
                f"got {len(server.handler.box)}"
            )
            assert server.handler.box[0] == expected_content, (
                f"{case_id}: handler content mismatch"
            )
            # The 250 that closes DATA proves the terminator was only accepted
            # at the intended position.
            assert server.reply_codes().count(250) == 4
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_split_terminator_does_not_end_data() -> None:
    # The five-octet terminator (including the preceding CRLF) is split at
    # every possible position; each split must still end exactly one mail.
    sequence = b"body\r\n.\r\n"

    async def scenario() -> None:
        for cut in range(1, len(sequence)):
            loop = asyncio.get_running_loop()
            server = InMemorySMTP(loop)
            try:
                await server.greet()
                await server.start_data()
                await server.send_chunks(
                    [sequence[:cut], sequence[cut:]]
                )
                assert len(server.handler.box) == 1, (
                    f"split at {cut}: unexpected transaction count"
                )
                assert server.handler.box[0] == b"body\r\n"
            finally:
                server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_bare_lf_does_not_become_next_mail() -> None:
    # Classic smuggling shape: a second MAIL/RCPT/DATA/250 sequence is hidden
    # behind a bare-LF fake terminator.  A strict server must deliver one mail
    # whose body still contains the hidden commands, and never open a second
    # transaction.
    smuggled = (
        b"From: anne@example.com\r\n"
        b"\r\n"
        b"visible body\n"
        b".\r\n"
        b"MAIL FROM:<attacker@example.com>\r\n"
        b"RCPT TO:<victim@example.com>\r\n"
        b"DATA\r\n"
        b"injected body\r\n"
        b".\r\n"
    )
    # The hidden block above uses the real terminator at its very end, so the
    # whole first DATA still closes normally with a single 250.
    wire = (
        b"EHLO example.com\r\n"
        b"MAIL FROM:<anne@example.com>\r\n"
        b"RCPT TO:<bart@example.com>\r\n"
        b"DATA\r\n" + smuggled
    )

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.send_chunks(bytes([octet]) for octet in wire)
            assert len(server.handler.box) == 1
            content = server.handler.box[0]
            # The "injected" commands must survive verbatim inside the body.
            assert b"MAIL FROM:<attacker@example.com>" in content
            assert b"RCPT TO:<victim@example.com>" in content
            assert b"injected body" in content
            # Exactly the four 250s of EHLO/MAIL/RCPT/DATA; the hidden MAIL
            # never produced a fifth one.
            assert server.reply_codes().count(250) == 4
            assert server.handler.envelopes[0].mail_from == (
                "anne@example.com"
            )
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_second_mail_on_same_connection_still_works() -> None:
    # Strictness must not break the legitimate pipelined multi-transaction
    # case: two fully compliant mails back to back.
    mail_one = b"first body\r\n.\r\n"
    mail_two = b"second body\r\n.\r\n"
    wire = (
        b"EHLO example.com\r\n"
        b"MAIL FROM:<a@example.com>\r\n"
        b"RCPT TO:<b@example.com>\r\n"
        b"DATA\r\n" + mail_one +
        b"MAIL FROM:<c@example.com>\r\n"
        b"RCPT TO:<d@example.com>\r\n"
        b"DATA\r\n" + mail_two +
        b"QUIT\r\n"
    )

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.send_chunks([wire])
            assert len(server.handler.box) == 2
            assert server.handler.box[0] == b"first body\r\n"
            assert server.handler.box[1] == b"second body\r\n"
            assert server.handler.envelopes[0].mail_from == "a@example.com"
            assert server.handler.envelopes[1].mail_from == "c@example.com"
            assert server.reply_codes().count(250) == 7
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_interrupted_stream_waits_for_crlf_then_resumes() -> None:
    # A terminator whose final CRLF is delayed must keep DATA open; nothing is
    # delivered until the missing octets arrive, then the single mail closes.
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.greet()
            await server.start_data()
            await server.send_chunks([b"body\r\n."])
            assert server.handler.box == []
            # Only greeting/EHLO/MAIL/RCPT/354 so far; no DATA 250 yet.
            assert server.last_reply_code() == 354
            # Deliver the missing CRLF in two more feeds to exercise buffering.
            await server.send_chunks([b"\r", b"\n"])
            assert len(server.handler.box) == 1
            assert server.handler.box[0] == b"body\r\n"
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_eof_inside_terminator_never_delivers() -> None:
    # The hard version of an interrupted stream: the connection ends after a
    # partial terminator ("body\r\n." with no closing CRLF).  No mail may be
    # delivered and no DATA 250 may be emitted; the incomplete transaction is
    # discarded rather than guessed into existence.
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.greet()
            await server.start_data()
            await server.send_chunks([b"body\r\n."])
            assert server.handler.box == []
            server.transport.feed_eof()
            await server.settle()
            assert server.handler.box == []
            assert 250 not in server.reply_codes()[4:]
            assert server.transport.is_closing()
        finally:
            # feed_eof() already ran connection_lost(); closing again is a
            # no-op via is_closing(), but suppress any double-callback noise.
            with contextlib.suppress(Exception):
                server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_relaxed_terminator_variant_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mutation test proving the corpus pins the CRLF-only boundary.

    We install a *temporary* lenient framing layer on the real StreamReader:
    when DATA asks for lines ending in CRLF the reader instead splits on any
    LF and re-suffixes the line with CRLF.  The strict ``line == b".\\r\\n"``
    check inside ``smtp_DATA`` then also fires after a bare-LF dot line.  This
    is exactly the class of leniency behind SMTP smuggling.  The test then
    asserts the concrete boundary confusion (a truncated body and an executed,
    attacker-owned second transaction), not a generic rejection message.

    The relaxed behavior is intentionally NOT shipped and has no configuration
    switch: accepting bare-LF/bare-CR terminators cannot be offered as an
    equally safe alternative to the strict RFC 5321 policy.
    """
    original_readuntil = asyncio.StreamReader.readuntil

    def lenient_readuntil(
        self: asyncio.StreamReader, separator: bytes = b"\n"
    ) -> _t.Coroutine:
        if separator != b"\r\n":
            return original_readuntil(self, separator)

        async def _drive() -> bytes:
            # Split on every LF, normalize either CR LF or a bare LF to a
            # canonical CRLF so downstream framing is byte-identical regardless
            # of which line ending the client actually used.
            line = await original_readuntil(self, b"\n")
            body = line[:-2] if line.endswith(b"\r\n") else line[:-1]
            return body + b"\r\n"

        return _drive()

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        # Only this connection's reader is relaxed; monkeypatch.undo() in the
        # fixture restores the class-wide method afterwards.
        monkeypatch.setattr(asyncio.StreamReader, "readuntil",
                            lenient_readuntil)
        try:
            await server.greet()
            await server.start_data()
            # A full smuggling payload: visible first mail, a bare-LF dot line
            # the lenient layer accepts as end-of-data, then a complete second
            # MAIL/RCPT/DATA transaction hidden in what strict mode treats as
            # the first mail's body.
            payload = (
                b"line one\n"
                b".\r\n"
                b"MAIL FROM:<attacker@example.com>\r\n"
                b"RCPT TO:<victim@example.com>\r\n"
                b"DATA\r\n"
                b"injected body\r\n"
                b".\r\n"
            )
            await server.send_chunks(bytes([octet]) for octet in payload)

            # The lenient boundary creates TWO transactions from one DATA
            # command; that is the smuggling primitive.
            assert len(server.handler.box) == 2
            first, second = server.handler.box
            # First mail is truncated at the bare-LF boundary (LF normalized
            # to CRLF by the lenient line adapter).
            assert first == b"line one\r\n", first
            # Second mail is the attacker-controlled content, delivered with
            # the attacker's envelope rather than the original sender's.
            assert second == b"injected body\r\n", second
            assert server.handler.envelopes[1].mail_from == (
                "attacker@example.com"
            )
            assert server.handler.envelopes[1].rcpt_tos == [
                "victim@example.com"
            ]
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_strict_corpus_rejects_the_lenient_framing_result() -> None:
    """
    Inverse of the lenient mutation, fed the identical smuggling payload.

    The strict server must produce exactly ONE transaction whose body still
    contains every byte of the would-be second transaction, and must never
    instantiate the attacker's envelope.
    """
    payload = (
        b"line one\n"
        b".\r\n"
        b"MAIL FROM:<attacker@example.com>\r\n"
        b"RCPT TO:<victim@example.com>\r\n"
        b"DATA\r\n"
        b"injected body\r\n"
        b".\r\n"
    )

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(loop)
        try:
            await server.greet()
            await server.start_data()
            await server.send_chunks(bytes([octet]) for octet in payload)
            assert len(server.handler.box) == 1
            content = server.handler.box[0]
            # Every injected byte survives as message content.
            assert content == payload[:-3], content
            assert b"MAIL FROM:<attacker@example.com>" in content
            assert b"injected body" in content
            # No second envelope; the original sender is untouched.
            assert server.handler.envelopes[0].mail_from == "anne@example.com"
            # Only the four legitimate success replies (EHLO/MAIL/RCPT/DATA).
            assert server.reply_codes().count(250) == 4
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))


def test_lmtp_inherits_strict_terminator() -> None:
    # LMTP subclasses SMTP and reuses smtp_DATA unchanged, so it must apply
    # the identical CRLF-only boundary; verify with a bare-LF smuggling shape.
    payload = b"line one\n.\r\nMAIL FROM:<evil@example.com>\r\n.\r\n"

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        server = InMemorySMTP(
            loop, protocol_factory=LMTP, greeting=b"LHLO example.com\r\n"
        )
        try:
            await server.greet()
            await server.start_data()
            await server.send_chunks(bytes([octet]) for octet in payload)
            assert len(server.handler.box) == 1
            assert server.handler.box[0] == payload[:-3]
            # The injected MAIL never became a second transaction.
            assert len(server.handler.envelopes) == 1
            assert server.handler.envelopes[0].mail_from == "anne@example.com"
        finally:
            server.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=WAIT_TIMEOUT))
