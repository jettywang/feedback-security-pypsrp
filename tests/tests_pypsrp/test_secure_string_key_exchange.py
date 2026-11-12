# -*- coding: utf-8 -*-

import base64
import logging
import struct
import uuid
import xml.etree.ElementTree as ET

import pytest
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from pypsrp.messages import (
    Destination,
    EncryptedSessionKey,
    Message,
    MessageType,
)
from pypsrp.powershell import (
    Fragment,
    PowerShell,
    RunspacePool,
)
from pypsrp.serializer import Serializer
from pypsrp.wsman import WSMan

# These are fake secrets used to verify the right key is used to decrypt a
# SecureString and that the plaintext never ends up in the test logs.
FAKE_SECRET_A = "FAKE-SECRET-alpha-not-a-real-credential"
FAKE_SECRET_B = "FAKE-SECRET-bravo-not-a-real-credential"

# Fixed session keys so the (in)ability to decrypt is deterministic.
SESSION_KEY_A = b"\xaa" * 32
SESSION_KEY_B = b"\xbb" * 32


def _new_pool():
    pool = RunspacePool(WSMan(""))
    # Simulate the client side of exchange_keys(); the RSA key pair exists and
    # the public key was sent, the pool is waiting for the server response.
    pool._exchange_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pool, PowerShell(pool)


def _session_key_fragment(pool, session_key, object_id):
    # Build the ENCRYPTED_SESSION_KEY message a server would send back.
    public_key = pool._exchange_key.public_key()
    encrypted_key = public_key.encrypt(session_key, asym_padding.PKCS1v15())
    # Win32 crypto blob header + little-endian encrypted key, mirrors
    # RunspacePool._process_encrypted_session_key.
    blob = b"\x00" * 12 + encrypted_key[::-1]
    msg = Message(
        Destination.CLIENT,
        pool.id,
        None,
        EncryptedSessionKey(session_key=base64.b64encode(blob).decode("utf-8")),
        Serializer(),
    )
    return Fragment(object_id, 0, msg.pack(), start=True, end=True).pack()


def _encrypt_secure_string(plaintext, session_key):
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-16-le")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(session_key), modes.CBC(b"\x00" * 16)).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode("utf-8")


def _secure_string_output_fragment(pool, ss_b64, object_id):
    # Build a PIPELINE_OUTPUT message with a raw SecureString element.
    data = struct.pack("<I", Destination.CLIENT)
    data += struct.pack("<I", MessageType.PIPELINE_OUTPUT)
    data += uuid.UUID(pool.id).bytes_le
    data += b"\x00" * 16  # empty pipeline id
    data += ("<SS>%s</SS>" % ss_b64).encode("utf-8")
    return Fragment(object_id, 0, data, start=True, end=True).pack()


def _assert_secrets_not_logged(caplog, *secrets):
    for record in caplog.records:
        for secret in secrets:
            assert secret not in record.getMessage(), "fake secret leaked into log: %s" % record.getMessage()


class TestSecureStringKeyExchange(object):
    def test_secure_string_before_key_exchange_returns_raw_element(self, caplog):
        pool, ps = _new_pool()
        key_frag = _session_key_fragment(pool, SESSION_KEY_A, object_id=1)
        out_frag = _secure_string_output_fragment(pool, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 2)

        with caplog.at_level(logging.DEBUG, logger="pypsrp"):
            # The SecureString output arrives before the key exchange has
            # completed, there is no cipher to interpret it with yet.
            early = pool._parse_responses(out_frag, pipeline=ps)

            assert not pool._key_exchanged
            assert early[0][0] == MessageType.PIPELINE_OUTPUT
            early_value = early[0][1].data.data
            assert isinstance(early_value, ET.Element)
            assert early_value.tag == "SS"
            # only the base64 ciphertext is exposed, never the plaintext
            assert FAKE_SECRET_A not in (early_value.text or "")

            # Once the key exchange completes the same secret is decrypted.
            pool._parse_responses(key_frag)
            assert pool._key_exchanged
            later = pool._parse_responses(
                _secure_string_output_fragment(pool, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 3),
                pipeline=ps,
            )
            assert later[0][1].data.data == FAKE_SECRET_A

        _assert_secrets_not_logged(caplog, FAKE_SECRET_A)

    def test_interleaved_key_exchange_two_runspace_pools(self, caplog):
        pool_a, ps_a = _new_pool()
        pool_b, ps_b = _new_pool()

        key_frag_a = _session_key_fragment(pool_a, SESSION_KEY_A, object_id=1)
        key_frag_b = _session_key_fragment(pool_b, SESSION_KEY_B, object_id=1)
        out_frag_a = _secure_string_output_fragment(pool_a, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 2)
        out_frag_b = _secure_string_output_fragment(pool_b, _encrypt_secure_string(FAKE_SECRET_B, SESSION_KEY_B), 2)

        with caplog.at_level(logging.DEBUG, logger="pypsrp"):
            # Interleave the two pools in memory: A gets its key, B gets its
            # key and output in a single receive, then A gets its output.
            pool_a._parse_responses(key_frag_a)
            res_b = pool_b._parse_responses(key_frag_b + out_frag_b, pipeline=ps_b)
            res_a = pool_a._parse_responses(out_frag_a, pipeline=ps_a)

            assert pool_a._key_exchanged
            assert pool_b._key_exchanged

            assert res_b[0][0] == MessageType.ENCRYPTED_SESSION_KEY
            assert res_b[1][0] == MessageType.PIPELINE_OUTPUT
            assert res_b[1][1].data.data == FAKE_SECRET_B
            assert res_a[0][1].data.data == FAKE_SECRET_A

            # each pool kept its own session key
            assert pool_a._serializer.cipher.algorithm.key == SESSION_KEY_A
            assert pool_b._serializer.cipher.algorithm.key == SESSION_KEY_B

            # B cannot interpret ciphertext meant for A's runspace
            foreign = _secure_string_output_fragment(
                pool_b, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 3
            )
            with pytest.raises(ValueError) as err:
                pool_b._parse_responses(foreign, pipeline=ps_b)
            assert "Invalid padding" in str(err.value)
            assert FAKE_SECRET_A not in str(err.value)

        _assert_secrets_not_logged(caplog, FAKE_SECRET_A, FAKE_SECRET_B)

    def test_secure_string_bad_ciphertext_raises_without_leaking(self, caplog):
        pool, ps = _new_pool()
        pool._parse_responses(_session_key_fragment(pool, SESSION_KEY_A, object_id=1))

        with caplog.at_level(logging.DEBUG, logger="pypsrp"):
            # ciphertext produced with a different session key
            wrong_key = _secure_string_output_fragment(
                pool, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_B), 2
            )
            with pytest.raises(ValueError) as err:
                pool._parse_responses(wrong_key, pipeline=ps)
            assert "Invalid padding" in str(err.value)
            assert FAKE_SECRET_A not in str(err.value)

            # truncated ciphertext that is not a multiple of the block size
            good_b64 = _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A)
            truncated = base64.b64encode(base64.b64decode(good_b64) + b"\x00").decode("utf-8")
            with pytest.raises(ValueError) as err:
                pool._parse_responses(_secure_string_output_fragment(pool, truncated, 3), pipeline=ps)
            assert "not a multiple of the block length" in str(err.value)
            assert FAKE_SECRET_A not in str(err.value)

            # an SS element with no ciphertext at all
            with pytest.raises(ValueError) as err:
                pool._parse_responses(_secure_string_output_fragment(pool, "", 4), pipeline=ps)
            assert "Invalid padding" in str(err.value)

        _assert_secrets_not_logged(caplog, FAKE_SECRET_A)

    def test_secure_string_empty_value(self, caplog):
        pool, ps = _new_pool()
        pool._parse_responses(_session_key_fragment(pool, SESSION_KEY_A, object_id=1))

        with caplog.at_level(logging.DEBUG, logger="pypsrp"):
            # a properly encrypted empty SecureString round trips to ""
            res = pool._parse_responses(
                _secure_string_output_fragment(pool, _encrypt_secure_string("", SESSION_KEY_A), 2),
                pipeline=ps,
            )
            assert res[0][0] == MessageType.PIPELINE_OUTPUT
            assert res[0][1].data.data == ""

        _assert_secrets_not_logged(caplog, FAKE_SECRET_A, FAKE_SECRET_B)

    def test_secure_string_after_reconnect_uses_new_key(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="pypsrp"):
            # first connection exchanges SESSION_KEY_A
            pool1, ps1 = _new_pool()
            pool1._parse_responses(_session_key_fragment(pool1, SESSION_KEY_A, object_id=1))
            res1 = pool1._parse_responses(
                _secure_string_output_fragment(pool1, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 2),
                pipeline=ps1,
            )
            assert res1[0][1].data.data == FAKE_SECRET_A

            # reconnect: a brand new pool performs a new key exchange and ends
            # up with a different session key
            pool2, ps2 = _new_pool()
            pool2._parse_responses(_session_key_fragment(pool2, SESSION_KEY_B, object_id=1))
            assert pool2._serializer.cipher.algorithm.key == SESSION_KEY_B

            # ciphertext from the old connection is rejected on the new one
            stale = _secure_string_output_fragment(pool2, _encrypt_secure_string(FAKE_SECRET_A, SESSION_KEY_A), 2)
            with pytest.raises(ValueError) as err:
                pool2._parse_responses(stale, pipeline=ps2)
            assert "Invalid padding" in str(err.value)
            assert FAKE_SECRET_A not in str(err.value)

            # output protected by the new key is interpreted correctly
            res2 = pool2._parse_responses(
                _secure_string_output_fragment(pool2, _encrypt_secure_string(FAKE_SECRET_B, SESSION_KEY_B), 3),
                pipeline=ps2,
            )
            assert res2[0][1].data.data == FAKE_SECRET_B

        _assert_secrets_not_logged(caplog, FAKE_SECRET_A, FAKE_SECRET_B)
