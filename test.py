import socket
from typing import List

from trapy import get_free_port, Conn, path, parse_address, Packet, random, checksum  # checksum2


# a = get_free_port(path)
# print(a)
#
# conn = Conn()
# conn.bind(('', a))


# def divide_data(data: bytes, length: int) -> List[bytes]:
#     divided_data = []
#     base = 0
#     while base < len(data):
#         upper = min(base + length, len(data))
#         divided_data.append(data[base:upper])
#         base += length
#
#     return divided_data
def divide_data(data: bytes, length: int) -> List[bytes]:
    divided_data = []
    base = 0
    while base < len(data):
        upper = min(base + length, len(data))
        if base == upper:
            divided_data.append(int.to_bytes(data[base], length=1, byteorder='big'))
        else:
            divided_data.append(data[base:upper])
        base += length

    return divided_data


# a = [i for i in range(15)]
# a = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\x33'
# print(bin(chksum(a)))
# print(bin(chksum2(a)))
# b = divide_data(a, 2)
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# print(b)
# for i in b:
# print(len(i))
# address = '10.0.0.2:1234'
# seq_number = random.randint(0, 2 ** 32 - 1)
# conn = Conn()
# conn.bind()
# address = parse_address(address)
# conn.set_dest(address)
# a = Packet(flags=0b00000001,
#            seq_number=seq_number,
#            src_port=conn.get_port(),
#            dest_port=address[1]
#            ).build()
#
# print(a)

a = Packet(src_port=1234, dest_port=4434, data=b'\x99')
packet = a.build()
s = (~checksum(packet)) & 0xffff
print(s, bin(s))


b = Packet(src_port=1234, dest_port=4434, data=b'\x99', checksum=s).build()
print(len(packet))
print(len(b))
print(bin(checksum(b)))
