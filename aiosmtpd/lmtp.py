# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any, List, Union

from public import public

from aiosmtpd.smtp import MISSING, SMTP, syntax


log = logging.getLogger(__name__)


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

    async def _finalize_data(self) -> None:
        """Push one final DATA reply per accepted recipient (RFC 2033)."""
        assert self.session is not None
        assert self.envelope is not None
        # Snapshot the accepted recipients before the envelope is reset.
        # Recipients rejected during RCPT never entered envelope.rcpt_tos,
        # so they occupy no slot in the replies.
        rcpt_tos = list(self.envelope.rcpt_tos)
        try:
            status = await self._call_data_hook()
        except Exception as error:
            # The handler failed mid-processing; every accepted recipient
            # still needs a final reply, and the connection must stay
            # usable for subsequent messages.
            try:
                status = await self.handle_exception(error)
            except Exception:
                status = '500 Error: Cannot describe error'
        statuses = self._per_recipient_statuses(status, len(rcpt_tos))
        self._set_post_data_state()
        for one_status in statuses:
            await self.push(one_status)

    def _per_recipient_statuses(
            self, status: Any, count: int
    ) -> List[Union[str, bytes]]:
        """Map a handle_DATA() result to one reply per accepted recipient."""
        if status is MISSING or status is None:
            return ['250 OK'] * count
        if isinstance(status, (str, bytes)):
            # A single status applies to all accepted recipients.
            return [status] * count
        try:
            statuses = list(status)
        except TypeError:
            statuses = []
        if (len(statuses) != count
                or not all(isinstance(s, (str, bytes)) for s in statuses)):
            log.error(
                'handle_DATA() must return None, a single status, or a list '
                'of %d status strings (one per accepted recipient); got %r',
                count, status)
            return ['451 4.3.0 Local error in processing'] * count
        return statuses
