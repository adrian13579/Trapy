import socket
import os
from typing import Tuple, Any, Optional
import random
from trapy.packet import Packet  # ,IPPacket
from trapy.timer import Timer
from trapy.utils import *
import logging

logger = logging.getLogger(__name__)
Address = Tuple[str, int]
path = "ports.trapy"


class Conn:
    def __init__(self):
        self.is_close = False
        self.__socket = socket.socket(socket.AF_INET,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_TCP)
        self.__socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.duration = 30

        self.N: int = 1
        self.send_base: int = 0
        self.send_base_sequence_number: int = 1

        self.recv_sequence_number: int = 0
        self.buffer: bytes = b''

        # bufsize =  ip_header + my_protocol_header + data
        self.max_data_packet = 512
        self.__default_bufsize: int = 20 + 20 + self.max_data_packet
        self.__dest_address: Optional[Address] = None
        self.__port: int = 0
        self.__host: str = ''
        self.__set_timeout(3)

    def __set_timeout(self, interval: float) -> None:
        self.__socket.settimeout(interval)

    def get_port(self) -> int:
        return self.__port

    def get_dest_address(self) -> Address:
        if self.__dest_address is None:
            raise ConnException("Destination address is not set")
        return self.__dest_address

    def set_dest(self, address: Address) -> None:
        self.__dest_address = address

    def close(self) -> None:
        self.N: int = 4
        self.send_base: int = 0

        self.recv_sequence_number: int = 0
        self.buffer: bytes = b''

        self.__dest_address: Optional[Address] = None
        self.__port: int = 0
        self.__host: str = ''

        self.is_close = True

    def bind(self, address: Address = None) -> None:
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

    def recv(self, timeout=0.5) -> Tuple[Optional[Packet], Any]:
        packet = Packet()
        address = ('', 0)
        self.__set_timeout(timeout)
        timer = Timer(timeout)
        timer.start()
        while True:
            try:
                data2, address = self.__socket.recvfrom(self.__default_bufsize)
                data = data2[20:]
                # print(f"Data recv: {data2}")
                packet.unpack(data)
                # print(f"Data recv: {data2}")
            except socket.timeout:
                timeout = timeout - timer.time()

            if packet.dest_port == self.__port:
                return packet, address

            if timer.timeout():
                return None, None
            self.__set_timeout(timeout)

    def send(self, data: bytes) -> int:
        if self.__dest_address is None:
            raise ConnException("Destination address is not set")
        data = make_ip_header(self.__dest_address[0]) + data
        # print(f'Data Send: {data}')
        # ip = IPPacket(src='10.0.0.1', dst=self.__dest_address[0])
        # ip_header = ip.assemble_ipv4_fields()
        # data = ip_header + data
        return self.__socket.sendto(data, self.__dest_address)


class ConnException(Exception):
    pass


def listen(address: str) -> Conn:
    conn = Conn()
    conn.bind(parse_address(address))
    print(f"Listening on address " + address)
    return conn


def accept(conn: Conn) -> Conn:
    while True:
        recv_packet, address = conn.recv(timeout=3)

        if recv_packet is None or corrupted(recv_packet.build()):
            continue

        conn_accepted = Conn()
        conn_accepted.bind()

        if index_bit(recv_packet.flags, SYN):
            print("First Packet Recv")
            logger.info("First Packet Recv")

            print(recv_packet.build())
            conn_accepted.set_dest((address[0], recv_packet.src_port))
            packet = Packet(flags=SYN_FLAG,
                            ack=bit32_sum(
                                recv_packet.seq_number, 1
                            ),
                            seq_number=0,
                            dest_port=recv_packet.src_port,
                            src_port=conn_accepted.get_port()
                            )
            conn_accepted.send(packet.build())
            recv_packet2, _ = conn_accepted.recv(timeout=4)
            if recv_packet2 is None:
                continue
            if recv_packet2.ack == 1 and not index_bit(recv_packet2.flags, SYN):
                return conn_accepted


def dial(address: str) -> Conn:
    conn = Conn()
    conn.bind()
    address = parse_address(address)
    conn.set_dest(address)

    while True:
        seq_number = random.randint(5, 2 ** 32 - 1)
        packet = Packet(flags=SYN_FLAG,
                        seq_number=seq_number,
                        src_port=conn.get_port(),
                        dest_port=address[1],
                        )
        conn.send(packet.build())
        logger.info("Dial send")
        packet_recv, new_address = conn.recv(timeout=3)
        if packet_recv is None:
            continue
        if packet_recv.ack == bit32_sum(packet.seq_number, 1) and index_bit(packet_recv.flags, SYN):
            conn.set_dest((new_address[0], packet_recv.src_port))
            count = 10
            while count:
                conn.send(Packet(
                    src_port=conn.get_port(),
                    ack=bit32_sum(packet_recv.seq_number, 1),
                    dest_port=conn.get_dest_address()[1],
                ).build())
                count -= 1
            return conn


def send(conn: Conn, data: bytes) -> int:
    if conn.is_close:
        return 0
    data_send = 0
    sender_timer = Timer(conn.duration)
    sender_timer.start()
    packets_data = divide_data(data, conn.max_data_packet)
    conn.send_base = 0

    timers = [Timer(1) for _ in range(len(packets_data))]
    is_packet_send = [False for i in range(len(packets_data))]

    print(f"LEN DATA: {len(packets_data)}")
    windows_recv_packets = 0
    window_timeout = False
    while conn.send_base < len(packets_data) and not sender_timer.timeout():
        window = range(conn.send_base, min(conn.send_base + conn.N, len(packets_data)))

        logger.info(f"WINDOW SIZE: {conn.N}")
        print(f"WINDOW SIZE : {conn.N}")

        for i, packet_index in enumerate(window):
            if not is_packet_send[packet_index] or timers[packet_index].timeout():
                flags = 0
                if packet_index == len(packets_data) - 1:
                    flags = LAST_FLAG
                p = Packet(src_port=conn.get_port(),
                           dest_port=conn.get_dest_address()[1],
                           seq_number=(conn.send_base_sequence_number + i) & 0xffffffff,
                           data_len=len(packets_data[packet_index]),
                           data=packets_data[packet_index],
                           flags=flags)
                is_packet_send[packet_index] = True
                print(f'SeqNum send:{p.seq_number}')
                logger.info(f'SeqNum send:{p.seq_number}')
                conn.send(p.build())

                if timers[packet_index].timeout():
                    window_timeout = True

                timers[packet_index] = Timer(0.5)
                timers[packet_index].start()

        recv_packet, _ = conn.recv()

        if recv_packet is not None and not corrupted(recv_packet.build()):

            # connection closed
            if index_bit(recv_packet.flags, FIN) and recv_packet.src_port == conn.get_dest_address()[1]:
                conn.send(Packet(
                    src_port=conn.get_port(),
                    dest_port=conn.get_dest_address()[1],
                    ack=bit32_sum(recv_packet.seq_number, 1),
                    flags=FIN_FLAG
                ).build())
                conn.close()
                return data_send

            sender_timer = Timer(conn.duration)
            sender_timer.start()

            print(f"Ack recv:{recv_packet.ack}")
            logger.info(f"Ack recv:{recv_packet.ack}")

            window = range(conn.send_base, min(conn.send_base + conn.N, len(packets_data)))
            for i, packet_index in enumerate(window):
                if (conn.send_base_sequence_number + i + 1) & 0xffffffff == recv_packet.ack:
                    data_send += len(packets_data[packet_index])
                    if packet_index >= conn.send_base:
                        windows_recv_packets += (packet_index - conn.send_base) + 1
                        conn.send_base_sequence_number = recv_packet.ack
                        conn.send_base = packet_index + 1
                    break

            if not window_timeout:
                if windows_recv_packets >= conn.N < 2 ** 31:
                    conn.N *= 2
                    windows_recv_packets = 0
            elif windows_recv_packets < conn.N != 1:
                conn.N //= 2
                windows_recv_packets = 0
                window_timeout = False

    return data_send


def recv(conn: Conn, length: int) -> bytes:
    if conn.is_close:
        return b''

    recv_timer = Timer(conn.duration)
    recv_timer.start()
    while len(conn.buffer) < length and not recv_timer.timeout():
        recv_packet, _ = conn.recv(timeout=0.5)

        if recv_packet is not None and not corrupted(recv_packet.build()):
            flags = 0
            recv_timer = Timer(conn.duration)
            recv_timer.start()

            # connection closed
            if index_bit(recv_packet.flags, FIN) and recv_packet.src_port == conn.get_dest_address()[1]:
                conn.send(Packet(
                    src_port=conn.get_port(),
                    dest_port=conn.get_dest_address()[1],
                    ack=bit32_sum(recv_packet.seq_number, 1),
                    flags=FIN_FLAG
                ).build())
                print(f'RECV SeqNum {recv_packet.seq_number}')
                print(f'SEND Ack {bit32_sum(recv_packet.seq_number, 1)}')

                print("FIN SEND ")
                data_recv = conn.buffer[:length]
                conn.buffer = conn.buffer[length:]
                conn.close()
                return data_recv

            print(f'SeqNum recv: {recv_packet.seq_number}')
            print(f'Expected SeqNum: {conn.recv_sequence_number + 1}')
            logger.info(f'SeqNum recv: {recv_packet.seq_number}')
            logger.info(f'Expected SeqNum: {conn.recv_sequence_number + 1}')
            # last ack was not recv in sender so it sends back the same ack
            if recv_packet.seq_number == conn.recv_sequence_number:
                conn.send(Packet(
                    src_port=conn.get_port(),
                    dest_port=conn.get_dest_address()[1],
                    ack=bit32_sum(recv_packet.seq_number, 1),
                    flags=flags
                ).build())

            if recv_packet.seq_number == bit32_sum(conn.recv_sequence_number, 1):
                conn.recv_sequence_number = recv_packet.seq_number
                conn.buffer += recv_packet.data[:recv_packet.data_len]

                if index_bit(recv_packet.flags, LAST):
                    flags = LAST_FLAG

                count = 10 if flags == LAST_FLAG else 1
                while count:
                    conn.send(Packet(
                        src_port=conn.get_port(),
                        dest_port=conn.get_dest_address()[1],
                        ack=bit32_sum(recv_packet.seq_number, 1),
                        flags=flags
                    ).build())
                    print(f"Ack send: {bit32_sum(recv_packet.seq_number, 1)}")
                    logger.info(f"Ack send: {bit32_sum(recv_packet.seq_number, 1)}")
                    count -= 1

            if flags == LAST_FLAG:
                break

    data_recv = conn.buffer[:length]
    conn.buffer = conn.buffer[length:]
    return data_recv


def close(conn: Conn):
    timer = Timer(conn.duration)
    timer.start()
    seq_number_send = []
    while not timer.timeout():

        seq_num = random.randint(3, 2 ** 32 - 1)
        seq_number_send.append(seq_num)
        try:
            conn.send(Packet(
                src_port=conn.get_port(),
                dest_port=conn.get_dest_address()[1],
                flags=FIN_FLAG,
                seq_number=seq_num
            ).build())
            print("FIN SEND")
        except ConnException:
            # conn is already closed or it's a listen conn
            break

        recv_packet, _ = conn.recv()

        if recv_packet is None or corrupted(recv_packet.build()):
            continue

        if index_bit(recv_packet.flags, FIN) \
                and any(bit32_sum(i, 1) == recv_packet.ack for i in seq_number_send):
            break

    conn.close()
