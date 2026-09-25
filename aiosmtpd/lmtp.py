# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import List, Union

from public import public

from aiosmtpd.smtp import MISSING, SMTP, syntax


log = logging.getLogger('mail.log')

#: Status pushed for every accepted recipient when the DATA handler fails
#: to provide a usable per-recipient result (exception raised, or a list
#: whose length does not match the number of accepted RCPT commands).
#: A 4xx code is used so the client knows to retry those recipients later.
HANDLER_ERROR_STATUS = '451 4.3.0 Message processing failed'


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
        """Push one final status line per accepted RCPT, in RCPT order.

        RFC 2033 requires an LMTP server to report, after the DATA phase,
        one final status for each recipient that was accepted with RCPT TO.
        The DATA handler may return a list of statuses, one per accepted
        recipient in the order their RCPT commands were accepted; recipients
        rejected during RCPT TO do not occupy a slot.  For convenience, a
        single status (or no status at all) applies to every recipient.
        """
        assert self.envelope is not None
        # Snapshot the accepted recipients before the state is reset, so a
        # following message on the same connection never sees them.
        rcpt_tos = list(self.envelope.rcpt_tos)
        try:
            status = await self._call_data_handler()
        except Exception:
            log.exception('%r DATA handler raised', self.session.peer)
            status = HANDLER_ERROR_STATUS
        self._set_post_data_state()
        num_rcpt = len(rcpt_tos)
        statuses: List[Union[str, bytes]]
        if status is MISSING:
            statuses = ['250 OK'] * num_rcpt
        elif isinstance(status, (str, bytes)):
            statuses = [status] * num_rcpt
        else:
            statuses = list(status)
            if len(statuses) != num_rcpt:
                log.warning(
                    '%r DATA handler returned %d statuses for %d recipients',
                    self.session.peer, len(statuses), num_rcpt)
                statuses = [HANDLER_ERROR_STATUS] * num_rcpt
        for one_status in statuses:
            await self.push(one_status)
