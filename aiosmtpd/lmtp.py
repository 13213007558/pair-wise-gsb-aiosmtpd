# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any, List

from public import public

from aiosmtpd.smtp import MISSING, SMTP, syntax


log = logging.getLogger(__name__)

# Deterministic per-recipient fallback used when the DATA handler's result
# cannot be mapped one-to-one onto the accepted recipients.  A temporary
# failure is the safe choice: the client may retry delivery later.
INVALID_STATUS_FALLBACK = '451 4.3.0 Error: Invalid DATA handler result'


def _valid_reply(status: Any) -> bool:
    """Whether status is a well-formed 2xx/4xx/5xx SMTP reply string."""
    if isinstance(status, bytes):
        try:
            status = status.decode('ascii')
        except UnicodeDecodeError:
            return False
    if not isinstance(status, str):
        return False
    code = status[:3]
    return (
        len(code) == 3
        and code.isdigit()
        and code[0] in ('2', '4', '5')
    )


@public
class LMTP(SMTP):
    show_smtp_greeting: bool = False

    @syntax('LHLO hostname')
    async def smtp_LHLO(self, arg: str) -> None:
        """The LMTP greeting, used instead of HELO/EHLO."""
        await super().smtp_EHLO(arg)

    async def smtp_HELO(self, arg: str) -> None:
        """HELO is not a valid LMTP command."""
        await self.push('500 Error: command "HELO" not recognized')

    async def smtp_EHLO(self, arg: str) -> None:
        """EHLO is not a valid LMTP command."""
        await self.push('500 Error: command "EHLO" not recognized')

    async def _get_data_status(self) -> Any:
        try:
            return await super()._get_data_status()
        except Exception as error:
            # RFC 2033 requires one final reply per accepted recipient, so a
            # handler exception must not escape to the generic single-reply
            # exception handler.  Convert it into a per-recipient status.
            status = await self.handle_exception(error)
            assert self.envelope is not None
            return [status] * len(self.envelope.rcpt_tos)

    async def _finalize_data(self, status: Any) -> None:
        """Send one final DATA reply per accepted recipient (RFC 2033)."""
        assert self.envelope is not None
        statuses = self._lmtp_statuses(status, len(self.envelope.rcpt_tos))
        self._set_post_data_state()
        for one_status in statuses:
            await self.push(one_status)

    def _lmtp_statuses(self, status: Any, rcpt_count: int) -> List[Any]:
        """Expand the DATA handler result into one reply per recipient.

        The result is fully validated before anything is sent, so a
        malformed handler result can never leave some recipients without
        a final reply.
        """
        if status is MISSING:
            return ['250 OK'] * rcpt_count
        if isinstance(status, (str, bytes)):
            # Backward compatibility: a single status applies to all
            # accepted recipients.
            return [status] * rcpt_count
        if isinstance(status, (list, tuple)):
            if len(status) != rcpt_count:
                log.error(
                    'DATA handler returned %d statuses for %d recipients',
                    len(status), rcpt_count)
                return [INVALID_STATUS_FALLBACK] * rcpt_count
            if all(_valid_reply(one_status) for one_status in status):
                return list(status)
            log.error('DATA handler returned an invalid status: %r', status)
            return [INVALID_STATUS_FALLBACK] * rcpt_count
        log.error('DATA handler returned an invalid status: %r', status)
        return [INVALID_STATUS_FALLBACK] * rcpt_count
