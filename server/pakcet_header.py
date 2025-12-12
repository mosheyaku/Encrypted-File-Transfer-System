import struct
from define import *


class RequestHeader:

    def __init__(self):
        self.id = ""
        self.version = 0
        self.code = 0
        self.payload_size = 0

    def parse_from_bytes(self, buf):
        self.id = buf[0:16].decode("utf-8")
        self.version, self.code, self.payload_size = struct.unpack_from("<BHI", buf, 16)


class RespondHeader:

    def __init__(self):
        self.version = VERSION
        self.code = 0
        self.payload_size = 0

    def pack_to_bytes(self):
        return struct.pack("<BHI", self.version, self.code, self.payload_size)
