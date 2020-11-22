import socket
import struct

from trapy.utils import checksum


class PacketException(Exception):
    pass


class Packet:
    def __init__(self,
                 data=None,
                 src_port=0,
                 dest_port=0,
                 seq_number=0,
                 ack=0,
                 data_len=0,
                 flags=0,
                 window=0,
                 ):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_number = seq_number
        self.ack = ack
        self.data_len = data_len
        self.flags = flags
        self.window = window
        self.checksum = 0
        self._max_size_data = 512
        self.data = data
        if data is None:
            self.data = bytearray(0)
        if len(self.data) > self._max_size_data:
            raise PacketException(f"Data size must not exceed {self._max_size_data} bytes")

        self._format = "!HHIIHHHH"
        self._padding_data()

    def _padding_data(self):
        padding = max(0, self._max_size_data - self.data_len)
        if padding:
            self.data += bytearray(padding)

    def build(self) -> bytes:
        self.checksum = 0
        packet = struct.pack(self._format,
                             self.src_port,
                             self.dest_port,
                             self.seq_number,
                             self.ack,
                             self.data_len,
                             self.flags,
                             self.window,
                             self.checksum
                             )
        packet += self.data
        self.checksum = (~checksum(packet)) & 0xffff
        packet = struct.pack(self._format,
                             self.src_port,
                             self.dest_port,
                             self.seq_number,
                             self.ack,
                             self.data_len,
                             self.flags,
                             self.window,
                             self.checksum
                             )
        packet += self.data
        return packet

    def unpack(self, packet: bytes) -> None:
        self.data = packet[20:20 + self._max_size_data]
        packet = packet[:20]
        info = struct.unpack(self._format, packet)
        self.src_port = info[0]
        self.dest_port = info[1]
        self.seq_number = info[2]
        self.ack = info[3]
        self.data_len = info[4]
        self.flags = info[5]
        self.window = info[6]
        self.checksum = info[7]


# class IPPacket:
#     def __init__(self, dst='127.0.0.1', src='192.168.1.101'):
#         self.dst = dst
#         self.src = src
#         self.raw = None
#         self.create_ipv4_feilds_list()
#
#     def assemble_ipv4_fields(self):
#         self.raw = struct.pack('!BBHHHBBH4s4s',
#                                self.ip_ver,  # IP Version
#                                self.ip_dfc,  # Differentiate Service Feild
#                                self.ip_tol,  # Total Length
#                                self.ip_idf,  # Identification
#                                self.ip_flg,  # Flags
#                                self.ip_ttl,  # Time to leave
#                                self.ip_proto,  # protocol
#                                self.ip_chk,  # Checksum
#                                self.ip_saddr,  # Source IP
#                                self.ip_daddr  # Destination IP
#                                )
#         return self.raw
#
#     def create_ipv4_feilds_list(self):
#         ip_ver = 4
#         ip_vhl = 5
#
#         self.ip_ver = (ip_ver << 4) + ip_vhl
#         ip_dsc = 0
#         ip_ecn = 0
#
#         self.ip_dfc = (ip_dsc << 2) + ip_ecn
#         self.ip_tol = 0
#
#         self.ip_idf = 54321
#
#         ip_rsv = 0
#         ip_dtf = 0
#         ip_mrf = 0
#         ip_frag_offset = 0
#         self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)
#
#         self.ip_ttl = 255
#
#         self.ip_proto = socket.IPPROTO_TCP
#
#         self.ip_chk = 0
#         self.ip_saddr = socket.inet_aton(self.src)
#
#         # ---- [ Destination Address ]
#         self.ip_daddr = socket.inet_aton(self.dst)
#
#         return
