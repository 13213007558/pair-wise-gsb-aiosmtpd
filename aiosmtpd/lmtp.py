# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

import logging
import re
from typing import Any, List

from public import public

from aiosmtpd.smtp import MISSING, SMTP, syntax


log = logging.getLogger('mail.log')


# A final per-recipient status must be a regular single-line SMTP reply
# with a 2xx, 4xx, or 5xx code (RFC 2033 section 4).
VALID_STATUS_RE = re.compile(r'[245][0-9][0-9](?: |$)')


def _valid_statuses(statuses: List[Any], count: int) -> bool:
    return (
        len(statuses) == count
        and all(
            isinstance(status, str) and VALID_STATUS_RE.match(status)
            for status in statuses
        )
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

    async def _push_data_status(
        self, status: Any, rcpt_tos: List[str]
    ) -> None:
        """Push one final DATA status per accepted recipient (RFC 2033).

        The handler may return a single status, which then applies to all
        accepted recipients, or a list of statuses corresponding
        one-to-one (and in order) to the accepted recipients. If the list
        does not match the accepted recipients exactly, or contains an
        invalid status, the whole transaction is failed with a temporary
        error before anything is sent, so the client never sees a partial
        set of replies.
        """
        count = len(rcpt_tos)
        statuses: List[Any]
        if status is MISSING:
            statuses = ['250 OK'] * count
        elif isinstance(status, (list, tuple)):
            if _valid_statuses(status, count):
                statuses = list(status)
            else:
                log.warning(
                    'Handler returned invalid per-recipient DATA statuses: %r',
                    status)
                statuses = [
                    '451 4.3.0 Invalid DATA statuses from handler'
                ] * count
        elif isinstance(status, (str, bytes)):
            statuses = [status] * count
        else:
            log.warning('Handler returned invalid DATA status: %r', status)
            statuses = ['451 4.3.0 Invalid DATA status from handler'] * count
        for one_status in statuses:
            await self.push(one_status)
