import socket
import os
from typing import Tuple, Any
import random
from packet import Packet
from timer import Timer
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
        # self.__socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self._default_bufsize = 44
        self.__dest_address: Address = None
        self.__port = 0
        self.__host = ''
        self.timeout = 3
        self._set_timeout(self.timeout)

    def _set_timeout(self, interval: float):
        self.__socket.settimeout(interval)

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
        #
        # if os.path.exists(path):
        #     file = open(path, 'r')
        #     lines = file.readlines()
        #     used_ports = list(map(int, lines[0].split()))
        #     if address[1] in used_ports:
        #         raise ConnException(f"Port {address[1]} in use")
        #     file.close()
        #     file = open('ports.trapy', 'a')
        #     file.write(f"{address[1]} ")
        # else:
        #     file = open('ports.trapy', 'w')
        #     file.write(f"{address[1]} ")
        self.__port = address[1]
        self.__host = address[0]
        # file.close()
        logger.info(f'socket binded to address {address}')

    def recv(self) -> Tuple[Packet, Any]:
        packet = Packet()
        address = ('', 0)
        time = 0
        self._set_timeout(self.timeout)
        while True:
            try:
                time = self.__socket.gettimeout()
                data2, address = self.__socket.recvfrom(self._default_bufsize)
                data = data2[20:]
                packet.unpack(data)
            except socket.timeout:
                self.timeout = max(0, self.timeout - time)
                self._set_timeout(self.timeout)

            if packet.dest_port == self.__port:
                return packet, address

            if self.timeout <= 0:
                return None, None

    def send(self, data: bytes):
        if self.__dest_address is None:
            raise ConnException("Destination address is not set")
        # data = make_ip_header(self.__dest_address[0]) + data
        return self.__socket.sendto(data, self.__dest_address)

    def sendto(self, data: bytes, address: Address):
        # data = make_ip_header(address[0]) + data
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
        print(conn.timeout)
        recv_packet, address = conn.recv()

        if recv_packet is None:
            continue

        if index_bit(recv_packet.flags, SYN):
            print("First Packet Recv")
            print(recv_packet.build())
            packet = Packet(flags=0b00000001,
                            ack=bit32_sum(
                                recv_packet.seq_number, 1
                            ),
                            seq_number=0,
                            dest_port=recv_packet.src_port,
                            src_port=conn.get_port()
                            )
            conn.sendto(packet.build(), (address[0], recv_packet.src_port))
            conn.timeout = 3
            recv_packet2, _ = conn.recv()
            if recv_packet2 is None:
                continue
            if recv_packet2.ack == 1 and not index_bit(recv_packet2.flags, SYN):
                conn.set_dest((address[0], recv_packet.src_port))
                return conn


def dial(address: str) -> Conn:
    conn = Conn()
    conn.bind()
    address = parse_address(address)
    conn.set_dest(address)

    while True:
        seq_number = random.randint(0, 2 ** 32 - 1)
        packet = Packet(flags=0b00000001,
                        seq_number=seq_number,
                        src_port=conn.get_port(),
                        dest_port=address[1],
                        )
        # print(packet.build())
        conn.send(packet.build())
        conn.timeout = 3
        packet_recv, _ = conn.recv()
        if packet_recv is None:
            continue
        if packet_recv.ack == bit32_sum(packet.seq_number, 1) and index_bit(packet_recv.flags, SYN):
            conn.send(Packet(
                src_port=conn.get_port(),
                ack=bit32_sum(packet_recv.seq_number, 1),
                dest_port=conn.get_dest_address()[1],
            ).build())
            return conn


def send(conn: Conn, data: bytes) -> int:
    seq_number = 1
    print(data)
    packets_data = divide_data(data, 2)
    timeout = 1
    timer = Timer(2)
    ack_recv = False
    while seq_number <= len(packets_data) or not ack_recv:
        conn.send(Packet(
            src_port=conn.get_port(),
            dest_port=conn.get_dest_address()[1],
            seq_number=seq_number,
            data_len=len(packets_data[seq_number - 1]),
            data=packets_data[seq_number - 1]
        ).build())
        p = Packet(
            src_port=conn.get_port(),
            dest_port=conn.get_dest_address()[1],
            seq_number=seq_number,
            data_len=len(packets_data[seq_number - 1]),
            data=packets_data[seq_number - 1]
        ).build()
        print(f'Packet send: {p}')
        timer.start()
        conn.timeout = timeout
        recv_packet, _ = conn.recv()
        if recv_packet is not None:
            print(f'Packet recv: {recv_packet.build()}')

        if recv_packet is not None:
            if recv_packet.ack == bit32_sum(seq_number, 1):
                seq_number = recv_packet.ack
                ack_recv = True

    return len(data)


def recv(conn: Conn, length: int) -> bytes:
    data_recv = bytearray(0)
    seq_number = 0
    while len(data_recv) < length:
        conn.timeout = 1
        recv_packet, _ = conn.recv()
        if recv_packet is not None:
            print(f'Packet recv: {recv_packet.build()}')

            if recv_packet.seq_number == bit32_sum(seq_number, 1):
                seq_number = recv_packet.seq_number
                data_recv += recv_packet.data[:recv_packet.data_len]
                print(recv_packet.data_len)
                print(recv_packet.data[:recv_packet.data_len])
                print(data_recv)

            conn.send(Packet(
                src_port=conn.get_port(),
                dest_port=conn.get_dest_address()[1],
                ack=bit32_sum(recv_packet.seq_number, 1),
            ).build())
            p = Packet(
                src_port=conn.get_port(),
                dest_port=conn.get_dest_address()[1],
                ack=bit32_sum(recv_packet.seq_number, 1),
            ).build()
            print(f"Packet send: {p}")
        print(f"Datarecv: {len(data_recv)}")
    return data_recv


def close(conn: Conn):
    pass
