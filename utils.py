import os
import random

SYN = 0
FIN = 1


def checksum(packet: bytes) -> int:
    bit_sum = 0
    for i in range(0, len(packet), 2):
        bit_sum += (packet[i] + packet[i + 1]) & 0xffff
    return bit_sum


def parse_address(address):
    host, port = address.split(':')

    if host == '':
        host = 'localhost'

    return host, int(port)


def bit32_sum(a, b):
    return (a + b) & 0xffffffff


def index_bit(n, i):
    return n >> i & 0b1


def get_free_port(path):
    if os.path.exists(path):
        file = open('ports.trapy', 'r')
        lines = file.readlines()
        free_ports = [i for i in range(1, 65536)]
        used_ports = list(map(int, lines[0].split()))
        for port in used_ports:
            free_ports.remove(port)

        index = random.randint(0, len(free_ports))
        file.close()
        return free_ports[index]

    return random.randint(1, 65536)
