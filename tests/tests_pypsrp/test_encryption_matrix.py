# Go-live checklist for WinRM client encryption combinations.
#
# Verifies, for every (auth, encryption, ssl) combination, whether pypsrp
#   a) refuses the configuration with a ValueError,
#   b) sends the SOAP envelope in the clear (application/soap+xml), or
#   c) sends a wrapped SOAP envelope (multipart/encrypted) after an initial
#      blank POST that drives the authentication handshake.
#
# A request double records the Content-Type and body of every prepared
# request so no real WinRM endpoint is needed.

import pytest
import requests

from pypsrp.encryption import WinRMEncryption
from pypsrp.wsman import (
    SUPPORTED_AUTHS,
    HttpCredSSPAuth,
    _TransportHTTP,
)

SOAP_CONTENT_TYPE = "application/soap+xml;charset=UTF-8"
WRAPPED_CONTENT_TYPE = (
    'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
)
KERBEROS_WRAPPED_CONTENT_TYPE = (
    'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"'
)
CREDSSP_WRAPPED_CONTENT_TYPE = (
    'multipart/encrypted;protocol="application/HTTP-CredSSP-session-encrypted";boundary="Encrypted Boundary"'
)

# auth providers that can bootstrap a message encryption context
ENCRYPTING_AUTHS = ["credssp", "kerberos", "negotiate", "ntlm"]
# auth providers without a session security context - wrapping is impossible
NON_ENCRYPTING_AUTHS = ["basic", "certificate"]

SAMPLE_MESSAGE = b"<s:Envelope>checklist</s:Envelope>"


class _FakeAuthContext:
    """Stands in for an established pyspnego/credssp security context."""

    def __init__(self, response_auth_header="negotiate"):
        self.response_auth_header = response_auth_header


class _FakeAuth:
    """Mimics the requests auth handler after the 401 handshake is done."""

    def __init__(self, hostname, response_auth_header="negotiate"):
        self.contexts = {hostname: _FakeAuthContext(response_auth_header)}

    def __call__(self, request):
        return request


class _FakeCredSSPAuth(_FakeAuth, HttpCredSSPAuth):
    pass


class _RequestDouble:
    """Records every prepared request instead of hitting the network.

    The first entry for a wrapping transport is the blank POST pypsrp sends
    so the auth handler can run its challenge/response handshake before the
    real (wrapped) message is re-sent.
    """

    def __init__(self, fail_wrapped_once=False):
        self.requests = []
        self._fail_wrapped_once = fail_wrapped_once

    def __call__(self, request, **kwargs):
        self.requests.append(request)
        if self._fail_wrapped_once and request.body is not None:
            self._fail_wrapped_once = False
            raise requests.ReadTimeout("simulated dropped connection")
        return b"<s:Envelope />"

    @property
    def content_types(self):
        return [r.headers.get("Content-Type") for r in self.requests]

    @property
    def bodies(self):
        return [r.body for r in self.requests]


def _build_transport(monkeypatch, recorder, auth, encryption, ssl, auth_handler=None):
    transport = _TransportHTTP("server", username="user", password="pass", auth=auth, encryption=encryption, ssl=ssl)

    session = requests.Session()
    if auth_handler is None:
        auth_handler = _FakeCredSSPAuth("server") if auth == "credssp" else _FakeAuth("server")
    session.auth = auth_handler
    monkeypatch.setattr(_TransportHTTP, "_build_session", lambda self: session)
    monkeypatch.setattr(_TransportHTTP, "_send_request", recorder)

    wrap_mock = lambda self, message: ("multipart/encrypted", b"WRAPPED(" + message + b")")
    monkeypatch.setattr(WinRMEncryption, "wrap_message", wrap_mock)
    return transport


def _expected_wrap_required(encryption, ssl):
    return encryption == "always" if ssl else encryption != "never"


@pytest.mark.parametrize("auth", SUPPORTED_AUTHS)
@pytest.mark.parametrize("encryption", ["auto", "always", "never"])
@pytest.mark.parametrize("ssl", [True, False], ids=["https", "http"])
def test_encryption_combination_matrix(monkeypatch, auth, encryption, ssl):
    wrap_required = _expected_wrap_required(encryption, ssl)

    if wrap_required and auth in NON_ENCRYPTING_AUTHS:
        with pytest.raises(ValueError, match="Cannot use message encryption with auth '%s'" % auth):
            _TransportHTTP("server", auth=auth, encryption=encryption, ssl=ssl)
        return

    recorder = _RequestDouble()
    transport = _build_transport(monkeypatch, recorder, auth, encryption, ssl)
    assert transport.wrap_required is wrap_required

    transport.send(SAMPLE_MESSAGE)

    if wrap_required:
        # blank POST drives the auth handshake, then the wrapped message is sent
        assert recorder.bodies[0] is None
        assert recorder.bodies[1] == b"WRAPPED(" + SAMPLE_MESSAGE + b")"
        assert recorder.content_types[1] == (
            CREDSSP_WRAPPED_CONTENT_TYPE if auth == "credssp" else WRAPPED_CONTENT_TYPE
        )
        assert len(recorder.requests) == 2
    else:
        assert recorder.bodies == [SAMPLE_MESSAGE]
        assert recorder.content_types == [SOAP_CONTENT_TYPE]


def test_http_auto_basic_is_rejected_before_any_request(monkeypatch):
    # a go-live guard: plain HTTP + basic auth + default encryption must fail
    # fast instead of silently sending credentials and SOAP in the clear
    recorder = _RequestDouble()
    with pytest.raises(ValueError, match="Cannot use message encryption with auth 'basic'"):
        _TransportHTTP("server", auth="basic", ssl=False)
    assert recorder.requests == []


def test_wrapped_send_reauthenticates_and_resends_after_timeout(monkeypatch):
    # when the wrapped send fails, the encryption state is invalidated and
    # pypsrp re-runs the blank auth POST before re-wrapping and re-sending
    recorder = _RequestDouble(fail_wrapped_once=True)
    transport = _build_transport(monkeypatch, recorder, "ntlm", "auto", ssl=False)

    transport.send(SAMPLE_MESSAGE, retries_on_read_timeout=1)

    assert recorder.bodies == [
        None,  # initial auth handshake
        b"WRAPPED(" + SAMPLE_MESSAGE + b")",  # first wrapped send - dropped
        None,  # re-authentication after the failure
        b"WRAPPED(" + SAMPLE_MESSAGE + b")",  # re-wrapped and re-sent
    ]
    assert recorder.content_types[1] == WRAPPED_CONTENT_TYPE
    assert recorder.content_types[3] == WRAPPED_CONTENT_TYPE


def test_kerberos_context_uses_kerberos_protocol_token(monkeypatch):
    recorder = _RequestDouble()
    auth_handler = _FakeAuth("server", response_auth_header="kerberos")
    transport = _build_transport(monkeypatch, recorder, "kerberos", "always", ssl=True, auth_handler=auth_handler)

    transport.send(SAMPLE_MESSAGE)

    assert recorder.content_types[1] == KERBEROS_WRAPPED_CONTENT_TYPE


def test_credssp_context_uses_credssp_protocol_token(monkeypatch):
    recorder = _RequestDouble()
    transport = _build_transport(
        monkeypatch, recorder, "credssp", "always", ssl=True, auth_handler=_FakeCredSSPAuth("server")
    )

    transport.send(SAMPLE_MESSAGE)

    assert recorder.content_types[1] == CREDSSP_WRAPPED_CONTENT_TYPE


def test_https_always_wrap_still_sends_wrapped_soap(monkeypatch):
    # reproducible config for endpoints that must always wrap, even over TLS
    recorder = _RequestDouble()
    transport = _build_transport(monkeypatch, recorder, "negotiate", "always", ssl=True)

    transport.send(SAMPLE_MESSAGE)

    assert recorder.content_types[1] == WRAPPED_CONTENT_TYPE
    assert recorder.bodies[1] != SAMPLE_MESSAGE
