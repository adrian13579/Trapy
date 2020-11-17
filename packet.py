import struct


class PacketException(Exception):
    pass


class Packet:
    def __init__(self,
                 src_port=0,
                 dest_port=0,
                 seq_number=0,
                 ack=0,
                 header_len=0,
                 flags=0,
                 window=0,
                 checksum=0,
                 data=bytearray(6)
                 ):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_number = seq_number
        self.ack = ack
        self.header_len = header_len
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self._max_size_data = 6

        if len(data) > self._max_size_data:
            raise PacketException(f"Data size must not exceed {self._max_size_data} bytes")
        self.data: bytes = data

        self._format = "HHIIbbHH"

    def build(self) -> bytes:
        packet = struct.pack(self._format,
                             self.src_port,
                             self.dest_port,
                             self.seq_number,
                             self.ack,
                             self.header_len,
                             self.flags,
                             self.window,
                             self.checksum
                             )
        packet += self.data
        return packet

    def unpack(self, packet: bytes) -> None:
        self.data = packet[18:18+self._max_size_data]
        packet = packet[:18]

        info = struct.unpack(self._format, packet)
        self.src_port = info[0]
        self.dest_port = info[1]
        self.seq_number = info[2]
        self.ack = info[3]
        self.header_len = info[4]
        self.flags = info[5]
        self.window = info[6]
        self.checksum = info[7]
