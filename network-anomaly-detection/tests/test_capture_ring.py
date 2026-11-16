import struct

import pytest

from netguard.capture import unpack_frame


def frame(length=5, captured=5, mac=64):
    buffer = bytearray(2048)
    struct.pack_into("=IIIHHII", buffer, 0, 1, length, captured, mac, 78, 123, 456789000)
    buffer[64:69] = b"hello"
    return buffer


def test_kernel_ring_timestamp_and_frame_ownership():
    buffer = frame()
    assert unpack_frame(buffer, 0, 2048) == (123456789, b"hello")
    assert unpack_frame(buffer, 0, 2048) is None


@pytest.mark.parametrize("length,captured,mac", [(8, 5, 64), (5, 5, 2046), (5, 5, 16)])
def test_truncated_ring_frame_is_rejected_and_released(length, captured, mac):
    buffer = frame(length, captured, mac)
    with pytest.raises(ValueError, match="Truncated"):
        unpack_frame(buffer, 0, 2048)
    assert struct.unpack_from("=I", buffer)[0] == 0
