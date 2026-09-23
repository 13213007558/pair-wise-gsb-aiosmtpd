# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SASL EXTERNAL auth mechanism (client-cert based)."""

import logging
import ssl
from base64 import b64encode
from contextlib import contextmanager, suppress
from smtplib import SMTP as SMTPClient
from typing import Any, Dict, Generator, List, Optional, Tuple

import pytest
import trustme

from aiosmtpd.controller import Controller
from aiosmtpd.testing.statuscodes import SMTP_STATUS_CODES as S

from .conftest import Global


# region #### Harness #################################################################

CLIENT_CN = "mail-client"
DEFAULT_IDENTITY = "mail-client@example.com"
DELEGATE_IDENTITY = "shared@example.com"
UTF8_IDENTITY = "us\u00e9r@example.com"

S504_AUTH_UNAVAIL = (504, b"5.5.4 Unrecognized authentication type")
S501_AUTH_NOTUTF8 = (501, b"5.5.2 Can't decode authzid as UTF-8")


def cert_common_name(peercert: Dict[str, Any]) -> Optional[str]:
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


class ExternalAuthorizer:
    """Decides whether the verified client cert may act as the given authzid."""

    def __init__(self) -> None:
        self.calls: List[Tuple[Dict[str, Any], Optional[str]]] = []

    def __call__(
        self, peercert: Dict[str, Any], authzid: Optional[str]
    ) -> Optional[str]:
        self.calls.append((peercert, authzid))
        if cert_common_name(peercert) != CLIENT_CN:
            return None
        if authzid is None:
            # Empty authzid: fall back to the certificate's default identity
            return DEFAULT_IDENTITY
        if authzid in (DEFAULT_IDENTITY, DELEGATE_IDENTITY, UTF8_IDENTITY):
            return authzid
        return None


def login_ok(mechanism: str, login: bytes, password: bytes) -> bool:
    return login == b"goodlogin" and password == b"goodpasswd"


class PeekingHandler:
    """Records the session's auth state whenever MAIL is received."""

    def __init__(self) -> None:
        # NOTE: attribute names must not start with "auth_", otherwise
        # SMTP would mistake them for AUTH mechanism hooks.
        self.seen_auth_data: Any = None
        self.seen_authenticated: Optional[bool] = None

    async def handle_MAIL(
        self, server, session, envelope, address, mail_options
    ) -> str:
        self.seen_auth_data = session.auth_data
        self.seen_authenticated = session.authenticated
        return "250 OK"


# endregion


# region #### Fixtures ################################################################


@pytest.fixture
def authorizer() -> ExternalAuthorizer:
    return ExternalAuthorizer()


@pytest.fixture
def ssl_context_clientauth_server(
    tls_certificate: trustme.LeafCert,
    tls_certificate_authority: trustme.CA,
) -> ssl.SSLContext:
    """
    Server-side SSL context that *requests* (but does not require) a client
    certificate and verifies it against the test CA when one is presented.
    """
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_certificate.configure_cert(ssl_ctx)
    tls_certificate_authority.configure_trust(ssl_ctx)
    ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
    return ssl_ctx


@pytest.fixture
def client_cert(tls_certificate_authority: trustme.CA) -> trustme.LeafCert:
    return tls_certificate_authority.issue_cert(
        CLIENT_CN, common_name=CLIENT_CN
    )


@pytest.fixture
def ssl_context_client_cert(
    ssl_context_client: ssl.SSLContext, client_cert: trustme.LeafCert
) -> ssl.SSLContext:
    """Client-side SSL context presenting the test client certificate."""
    client_cert.configure_cert(ssl_context_client)
    return ssl_context_client


@pytest.fixture
def external_controller(
    get_controller, ssl_context_clientauth_server, authorizer
) -> Generator[Controller, None, None]:
    handler = PeekingHandler()
    controller = get_controller(
        handler,
        require_starttls=True,
        tls_context=ssl_context_clientauth_server,
        auth_external_callback=authorizer,
        auth_callback=login_ok,
    )
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    with suppress(AssertionError):
        controller.stop()


@pytest.fixture
def external_authreq_controller(
    get_controller, ssl_context_clientauth_server, authorizer
) -> Generator[Controller, None, None]:
    handler = PeekingHandler()
    controller = get_controller(
        handler,
        require_starttls=True,
        auth_required=True,
        tls_context=ssl_context_clientauth_server,
        auth_external_callback=authorizer,
        auth_callback=login_ok,
    )
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    with suppress(AssertionError):
        controller.stop()


@pytest.fixture
def external_nocallback_controller(
    get_controller, ssl_context_clientauth_server
) -> Generator[Controller, None, None]:
    """TLS client-auth capable server WITHOUT an auth_external_callback."""
    handler = PeekingHandler()
    controller = get_controller(
        handler,
        require_starttls=True,
        tls_context=ssl_context_clientauth_server,
    )
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    with suppress(AssertionError):
        controller.stop()


@pytest.fixture
def plaintext_controller(
    get_controller, authorizer
) -> Generator[Controller, None, None]:
    """Non-TLS server with auth_require_tls=False and an EXTERNAL callback."""
    handler = PeekingHandler()
    controller = get_controller(
        handler,
        auth_require_tls=False,
        auth_external_callback=authorizer,
    )
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    with suppress(AssertionError):
        controller.stop()


@contextmanager
def tls_client(client_ssl_context: ssl.SSLContext) -> Generator[SMTPClient, None, None]:
    """Connect, STARTTLS with the given context, and re-EHLO."""
    client = SMTPClient(*Global.SrvAddr)
    try:
        client.ehlo("example.com")
        code, resp = client.starttls(context=client_ssl_context)
        assert code == 220
        client.ehlo("example.com")
        yield client
    finally:
        client.close()


def auth_mechanisms(client: SMTPClient) -> List[str]:
    return client.esmtp_features.get("auth", "").split()


# endregion


@pytest.mark.usefixtures("external_controller")
class TestExternalAdvertisement:
    def test_advertised_with_verified_client_cert(
        self, ssl_context_client_cert
    ):
        with tls_client(ssl_context_client_cert) as client:
            assert "EXTERNAL" in auth_mechanisms(client)

    def test_not_advertised_without_client_cert(self, ssl_context_client):
        # Encrypted connection, but TLS never verified a peer certificate
        with tls_client(ssl_context_client) as client:
            assert "EXTERNAL" not in auth_mechanisms(client)
            # LOGIN/PLAIN must still be offered
            assert "PLAIN" in auth_mechanisms(client)
            assert "LOGIN" in auth_mechanisms(client)

    def test_auth_external_refused_without_client_cert(
        self, ssl_context_client
    ):
        with tls_client(ssl_context_client) as client:
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S504_AUTH_UNAVAIL

    def test_auth_external_refused_with_unverified_cert_field(
        self, ssl_context_client
    ):
        # A certificate-like blob is not a verified TLS peer certificate
        with tls_client(ssl_context_client) as client:
            resp = client.docmd(
                "AUTH EXTERNAL", b64encode(b"anything").decode()
            )
            assert resp == S504_AUTH_UNAVAIL


@pytest.mark.usefixtures("plaintext_controller")
class TestExternalPlaintext:
    def test_not_advertised_on_plaintext(self):
        with SMTPClient(*Global.SrvAddr) as client:
            client.ehlo("example.com")
            assert "EXTERNAL" not in auth_mechanisms(client)

    def test_auth_external_refused_on_plaintext(self):
        with SMTPClient(*Global.SrvAddr) as client:
            client.ehlo("example.com")
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S504_AUTH_UNAVAIL


@pytest.mark.usefixtures("external_nocallback_controller")
class TestExternalNoCallback:
    def test_not_advertised_without_callback(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            assert "EXTERNAL" not in auth_mechanisms(client)

    def test_refused_without_callback(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S504_AUTH_UNAVAIL


@pytest.mark.usefixtures("external_controller")
class TestExternalAuth:
    def test_default_identity_initial_response(
        self, ssl_context_client_cert, external_controller, authorizer
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S235_AUTH_SUCCESS
            # Empty authzid means "use the certificate's default identity"
            assert authorizer.calls[-1][1] is None
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_auth_data == DEFAULT_IDENTITY
        assert handler.seen_authenticated is True

    def test_default_identity_challenge_response(
        self, ssl_context_client_cert, external_controller, authorizer
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            code, resp = client.docmd("AUTH EXTERNAL")
            assert (code, resp) == S.S334_AUTH_EMPTYPROMPT
            # Empty response to the challenge: empty authzid
            resp = client.docmd("")
            assert resp == S.S235_AUTH_SUCCESS
            assert authorizer.calls[-1][1] is None
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_auth_data == DEFAULT_IDENTITY
        assert handler.seen_authenticated is True

    def test_delegate_identity_initial_response(
        self, ssl_context_client_cert, external_controller, authorizer
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd(
                "AUTH EXTERNAL", b64encode(DELEGATE_IDENTITY.encode()).decode()
            )
            assert resp == S.S235_AUTH_SUCCESS
            assert authorizer.calls[-1][1] == DELEGATE_IDENTITY
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_auth_data == DELEGATE_IDENTITY
        assert handler.seen_authenticated is True

    def test_delegate_identity_challenge_response(
        self, ssl_context_client_cert, external_controller
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            code, resp = client.docmd("AUTH EXTERNAL")
            assert code == 334
            resp = client.docmd(b64encode(DELEGATE_IDENTITY.encode()).decode())
            assert resp == S.S235_AUTH_SUCCESS
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_auth_data == DELEGATE_IDENTITY

    def test_utf8_authzid(
        self, ssl_context_client_cert, external_controller, authorizer
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd(
                "AUTH EXTERNAL",
                b64encode(UTF8_IDENTITY.encode("utf-8")).decode(),
            )
            assert resp == S.S235_AUTH_SUCCESS
            assert authorizer.calls[-1][1] == UTF8_IDENTITY
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_auth_data == UTF8_IDENTITY

    def test_wrong_authzid_rejected(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd(
                "AUTH EXTERNAL", b64encode(b"evil@example.com").decode()
            )
            assert resp == S.S535_AUTH_INVALID

    def test_bad_base64(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "!!!not-b64!!!")
            assert resp == S.S501_AUTH_NOTB64

    def test_bad_utf8_authzid(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd(
                "AUTH EXTERNAL", b64encode(b"\xff\xfe").decode()
            )
            assert resp == S501_AUTH_NOTUTF8

    def test_abort_initial_response(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "*")
            assert resp == S.S501_AUTH_ABORTED

    def test_abort_challenge_response(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            code, resp = client.docmd("AUTH EXTERNAL")
            assert code == 334
            resp = client.docmd("*")
            assert resp == S.S501_AUTH_ABORTED


@pytest.mark.usefixtures("external_controller")
class TestExternalSessionBinding:
    def test_rset_keeps_authentication(
        self, ssl_context_client_cert, external_controller
    ):
        handler: PeekingHandler = external_controller.handler
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S235_AUTH_SUCCESS
            resp = client.rset()
            assert resp == S.S250_OK
            # RSET must not tear down the completed authentication
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S503_ALREADY_AUTH
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        assert handler.seen_authenticated is True

    def test_login_plain_still_work(self, ssl_context_client):
        # Existing LOGIN/PLAIN behavior is unaffected by EXTERNAL support
        with tls_client(ssl_context_client) as client:
            resp = client.login("goodlogin", "goodpasswd")
            assert resp == S.S235_AUTH_SUCCESS


@pytest.mark.usefixtures("external_authreq_controller")
class TestExternalAuthRequired:
    def test_auth_required_enforced(self, ssl_context_client_cert):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.mail("alice@example.com")
            assert resp == S.S530_AUTH_REQUIRED
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S235_AUTH_SUCCESS
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK

    def test_new_tls_handshake_requires_reauth(
        self, ssl_context_client_cert
    ):
        with tls_client(ssl_context_client_cert) as client:
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S235_AUTH_SUCCESS
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK
        # A brand-new TLS handshake creates a brand-new session; the previous
        # authentication must NOT carry over.
        with tls_client(ssl_context_client_cert) as client:
            resp = client.mail("alice@example.com")
            assert resp == S.S530_AUTH_REQUIRED
            resp = client.docmd("AUTH EXTERNAL", "=")
            assert resp == S.S235_AUTH_SUCCESS
            resp = client.mail("alice@example.com")
            assert resp == S.S250_OK


@pytest.mark.usefixtures("external_controller")
class TestExternalLogging:
    def test_no_sensitive_data_logged(
        self, caplog, ssl_context_client_cert
    ):
        authzid_b64 = b64encode(DELEGATE_IDENTITY.encode()).decode()
        with caplog.at_level(logging.DEBUG, logger="mail.log"):
            with tls_client(ssl_context_client_cert) as client:
                resp = client.docmd("AUTH EXTERNAL", authzid_b64)
                assert resp == S.S235_AUTH_SUCCESS
        # Neither the raw SASL response nor the authzid may appear in logs
        assert authzid_b64 not in caplog.text
        assert DELEGATE_IDENTITY not in caplog.text
