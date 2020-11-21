import socket
import struct
from trapy import *
from packet import Packet

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.bind(('', 5555))

# s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# s1.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# s1.bind(('', 6666))

# while True:
#     print("First Part----------------------")
#     data, b = s.recvfrom(65565)
#     print(data)
#     a = Packet()
#     a.unpack(data[20:])
#     print(a.seq_number)
#     data = data[20:]
#     print(len(data))
#     packet = Packet()
#     packet.unpack(data)
#     print(packet.src_port)
#     print("Second Part-----------")
#     s.sendto(data, ('10.0.0.1',0))
# data2, a = s1.recvfrom(65565)
# print(a)
# packet = Packet()
# data2 = data2[20:]
# packet.unpack(data2)
# print(packet.data)
print("--------------------------")
server = listen('127.0.0.1:1234')
print('Listen finished')
conn = accept(server)
print('Accept ')
# print(recv(conn, 5))
a = recv(conn, 15)
print(f"RECIBIDO FINAL A: {a}  {len(a)}")
print("Recibiiiiiiiiiiiiiiiiiiiiiiiiiiii")
# b = recv(conn, 7)
# print(f"RECIBIDO FINAL B: {b} {len(b)}")
#
# c = recv(conn, 7)
# print(f"RECIBIDO FINAL C: {c} {len(c)}")
#
# d = recv(conn, 3)
# print(f"RECIBIDO FINAL D: {d} {len(d)}")


#  print(len(data))
#  data = struct.unpack("?i",data.decode())
# # print(a)
#  print('Hola')
# print(b)
# print(s.recvfrom(65565))
