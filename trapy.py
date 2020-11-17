import socket
import os
from typing import Tuple, Any
import random
from packet import Packet
from utils import *
import logging

logger = logging.getLogger(__name__)
Address = Tuple[str, int]
path = "ports.trapy"


class Conn:
    def __init__(self):
        self.__socket = socket.socket(socket.AF_INET,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_TCP)
        self._default_bufsize = 65565
        self.__dest_address: Address = None
        self.__port = 0
        self.__host = ''

    def get_port(self):
        return self.__port

    def get_dest_address(self):
        return self.__dest_address

    def set_dest(self, address: Address):
        if self.__dest_address is not None:
            raise ConnException(f"Destination address already set :{self.__dest_address}")
        self.__dest_address = address

    def bind(self, address: Address = None):
        if address is None:
            address = ('', get_free_port(path))

        if os.path.exists(path):
            file = open(path, 'r')
            lines = file.readlines()
            used_ports = list(map(int, lines[0].split()))
            if address[1] in used_ports:
                raise ConnException(f"Port {address[1]} in use")
            file.close()
            file = open('ports.trapy', 'a')
            file.write(f"{address[1]} ")
        else:
            file = open('ports.trapy', 'w')
            file.write(f"{address[1]} ")
        self.__port = address[1]
        file.close()
        logger.info(f'socket binded to address {address}')

    def recv(self, bufsize: int = None) -> Tuple[bytes, Any]:
        if bufsize is None:
            bufsize = self._default_bufsize
        data, address = self.__socket.recvfrom(bufsize)
        data = data[20:]
        return data, address

    def recv_packet(self) -> Tuple[Packet, Any]:
        data, address = self.__socket.recvfrom(self._default_bufsize)
        data = data[20:]
        packet = Packet()
        packet.unpack(data)

        if packet.dest_port == self.__port:
            return packet, address
        return Packet(), None

    def send(self, data: bytes):
        if self.__dest_address is None:
            raise ConnException("Destination address is not set")
        return self.__socket.sendto(data, self.__dest_address)

    def sendto(self, data: bytes, address: Address):
        return self.__socket.sendto(data, address)


class ConnException(Exception):
    pass


def listen(address: str) -> Conn:
    conn = Conn()
    conn.bind(parse_address(address))
    print(f"Listening on address " + address)
    return conn


def accept(conn: Conn) -> Conn:
    while True:
        print("Waiting for dial")
        recv_packet, address = conn.recv_packet()
        print("Dial received")
        if recv_packet.flags == 1:
            packet = Packet(flags=1,
                            ack=bit32_sum(
                                recv_packet.seq_number, 1
                            ),
                            seq_number=0,
                            dest_port=recv_packet.src_port,
                            src_port=conn.get_port()
                            )
            conn.sendto(packet.build(), (address[0], recv_packet.src_port))
            recv_packet2, _ = conn.recv_packet()
            print(recv_packet2.ack)
            print(recv_packet2.flags)
            if recv_packet2.ack == 1 and recv_packet2.flags == 0:
                conn.set_dest((address[0], recv_packet.src_port))
                return conn


def dial(address: str) -> Conn:
    conn = Conn()
    conn.bind()
    address = parse_address(address)
    conn.set_dest(address)

    print(conn.get_port())
    print(conn.get_dest_address())
    print(address[1])
    while True:
        seq_number = random.randint(0, 2 ** 32 - 1)
        packet = Packet(flags=1,
                        seq_number=seq_number,
                        src_port=conn.get_port(),
                        dest_port=address[1]
                        )
        print(packet.build())
        conn.send(packet.build())
        print("Packet Send")
        packet_recv, _ = conn.recv_packet()
        print("Packet Received")
        print(packet_recv, _)
        print(packet_recv.flags)
        print("Hola")
        if packet_recv.ack == bit32_sum(packet.seq_number, 1) and packet_recv.flags == 1:
            packet2 = Packet(
                src_port=conn.get_port(),
                ack=bit32_sum(packet_recv.seq_number, 1),
                dest_port=conn.get_dest_address()[1]
            ).build()
            conn.send(packet2)
            print("Lo envie")
            return conn


def send(conn: Conn, data: bytes) -> int:
    pass


def recv(conn: Conn, length: int) -> bytes:
    pass


def close(conn: Conn):
    pass
