import socket
import struct
# from trapy import *
# from packet import *
# from trapy import divide_data
class IPPacket:
    def __init__(self, dst='127.0.0.1', src='192.168.1.101'):
        self.dst = dst
        self.src = src
        self.raw = None
        self.create_ipv4_feilds_list()

    def assemble_ipv4_fields(self):
        self.raw = struct.pack('!BBHHHBBH4s4s',
                               self.ip_ver,  # IP Version
                               self.ip_dfc,  # Differentiate Service Feild
                               self.ip_tol,  # Total Length
                               self.ip_idf,  # Identification
                               self.ip_flg,  # Flags
                               self.ip_ttl,  # Time to leave
                               self.ip_proto,  # protocol
                               self.ip_chk,  # Checksum
                               self.ip_saddr,  # Source IP
                               self.ip_daddr  # Destination IP
                               )
        return self.raw

    def create_ipv4_feilds_list(self):
        # ---- [Internet Protocol Version] ----
        ip_ver = 4
        ip_vhl = 5

        self.ip_ver = (ip_ver << 4) + ip_vhl

        # ---- [ Differentiate Servic Field ]
        ip_dsc = 0
        ip_ecn = 0

        self.ip_dfc = (ip_dsc << 2) + ip_ecn

        # ---- [ Total Length]
        self.ip_tol = 0

        # ---- [ Identification ]
        self.ip_idf = 54321

        # ---- [ Flags ]
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)

        # ---- [ Total Length ]
        self.ip_ttl = 255

        # ---- [ Protocol ]
        self.ip_proto = socket.IPPROTO_TCP

        # ---- [ Check Sum ]
        self.ip_chk = 0

        # ---- [ Source Address ]
        self.ip_saddr = socket.inet_aton(self.src)

        # ---- [ Destination Address ]
        self.ip_daddr = socket.inet_aton(self.dst)

        return
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
ip_header += b'\x0a\x00\x00\x01'  # Source Address
ip_header += b'\x0a\x00\x00\x02'  # Destination Address

tcp_header = b'\x30\x39\x00\x50'  # Source Port | Destination Port
tcp_header += b'\x00\x00\x00\x00'  # Sequence Number
tcp_header += b'\x00\x00\x00\x00'  # Acknowledgement Number
tcp_header += b'\x50\x02\x71\x10'  # Data Offset, Reserved, Flags | Window Size
tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

tcp_header += bytearray(512)

ip = IPPacket(src='10.0.0.1', dst='10.0.0.2')
ip_header = ip.assemble_ipv4_fields()
packet = ip_header + tcp_header
s.sendto(packet, ('10.0.0.2', 0))

# conn = dial('10.0.0.2:1234')
# data = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\x33'
# # # print(divide_data(data, 6))
# print(send(conn, data))
# close(conn)
#
# print(send(conn, data))
# a = Packet(seq_number=12, data=data).build()
# s.sendto(a, ('10.0.0.2', 0))
