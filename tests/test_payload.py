import binascii
import struct

import pytest

from eps_probe import payload
from eps_probe.protocol import build_region_request


def fake_shellcode(size=0x200):
    return b"\xAA" * size


def sample_request_block():
    return build_region_request(0, [(0x18000, 0x1000)])


def test_envelope_length_is_exact():
    envelope = payload.build_envelope(
        fake_shellcode(), sample_request_block()
    )
    assert len(envelope) == payload.PAYLOAD_ENVELOPE_LEN
    assert len(envelope) == 0x1000


def test_request_block_embedded_at_offset():
    request_block = sample_request_block()
    envelope = payload.build_envelope(fake_shellcode(), request_block)
    decrypted = payload.decrypt_envelope(envelope)
    assert (
        decrypted[payload.REQUEST_OFFSET:payload.REQUEST_OFFSET + len(request_block)]
        == request_block
    )


def test_jmp_addr_at_jmp_offset():
    envelope = payload.build_envelope(
        fake_shellcode(), sample_request_block()
    )
    decrypted = payload.decrypt_envelope(envelope)
    jmp = decrypted[payload.JMP_OFFSET:payload.JMP_OFFSET + 4]
    assert jmp == struct.pack("<I", 0xFEBF0000)


def test_crc_self_consistent():
    envelope = payload.build_envelope(
        fake_shellcode(), sample_request_block()
    )
    decrypted = payload.decrypt_envelope(envelope)
    assert binascii.crc32(decrypted[:0xFF0]) == 0xFFFFFFFF


def test_wrong_secret_fails_to_authenticate():
    did_201 = b"\x11" * 16
    envelope = payload.build_envelope(
        fake_shellcode(), sample_request_block(), did_201=did_201
    )
    with pytest.raises(ValueError):
        payload.decrypt_envelope(envelope, did_201=b"\x22" * 16)


def test_roundtrip_preserves_shellcode():
    shellcode = fake_shellcode()
    request_block = sample_request_block()
    envelope = payload.build_envelope(shellcode, request_block)
    decrypted = payload.decrypt_envelope(envelope)
    assert decrypted[:len(shellcode)] == shellcode


def test_rejects_oversized_shellcode():
    with pytest.raises(ValueError):
        payload.build_envelope(b"\xAA" * payload.JMP_OFFSET, sample_request_block())


def test_rejects_oversized_request_block():
    with pytest.raises(ValueError):
        payload.build_envelope(
            fake_shellcode(), b"\x00" * (payload.REQUEST_OFFSET - 0x100 + 1)
        )
