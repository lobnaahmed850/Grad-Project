"""Bounded Linux TPACKET_V2 capture ring with kernel packet timestamps."""
import mmap
import select
import socket
import struct


def unpack_frame(buffer, offset, frame_size):
    status, length, captured, mac, _, seconds, nanoseconds = struct.unpack_from("=IIIHHII", buffer, offset)
    if not status & 1:
        return None
    try:
        if captured != length or mac < 32 or mac + captured > frame_size or nanoseconds >= 1000000000:
            raise ValueError("Truncated or invalid capture-ring frame")
        return seconds * 1000000 + nanoseconds // 1000, bytes(buffer[offset + mac:offset + mac + captured])
    finally:
        struct.pack_into("=I", buffer, offset, 0)


class PacketRing:
    def __init__(self, interface, megabytes=32):
        if not isinstance(megabytes, int) or not 8 <= megabytes <= 256:
            raise ValueError("Capture ring must be 8..256 MiB")
        self.frame_size = 2048
        self.frames = megabytes * 1024 * 1024 // self.frame_size
        self.position = 0
        self.truncated = 0
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        try:
            self.sock.bind((interface, 0))
            self.sock.setsockopt(263, 10, struct.pack("=I", 1))
            self.sock.setsockopt(263, 5, struct.pack("=IIII", 1024 * 1024, megabytes, self.frame_size, self.frames))
            self.buffer = mmap.mmap(self.sock.fileno(), megabytes * 1024 * 1024,
                                    flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except BaseException:
            self.sock.close()
            raise

    def receive(self, timeout=.05):
        offset = self.position * self.frame_size
        if not struct.unpack_from("=I", self.buffer, offset)[0] & 1:
            select.select([self.sock], [], [], timeout)
        try:
            result = unpack_frame(self.buffer, offset, self.frame_size)
        except ValueError:
            self.truncated += 1
            result = ()
        if result is not None:
            self.position = (self.position + 1) % self.frames
        return result

    def dropped(self):
        return struct.unpack("=II", self.sock.getsockopt(263, 6, 8))[1]

    def close(self):
        self.buffer.close()
        self.sock.close()
