import array
import os
import random
import subprocess
import shlex
from typing import List

SYN = 0
FIN = 1


def chksum(packet):
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff


def chksum2(packet):
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return res


def make_ip_header(dest: str) -> bytes:
    ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum

    host = '10.0.0.1'

    def host_ip(cod):
        temp1 = str(cod, 'utf8').split('src')
        temp2 = temp1[1].split('uid')
        return temp2[0].split()[0]

    sub = subprocess.check_output(shlex.split(f'ip route get to {host}'))

    source_ip = host_ip(sub)
    for i in source_ip.split('.'):
        ip_header += int(i).to_bytes(length=1, byteorder='little')

    for i in dest.split('.'):
        ip_header += int(i).to_bytes(length=1, byteorder='little')

    return ip_header


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


def checksum(packet: bytes) -> int:
    bit_sum = 0
    for i in range(0, len(packet), 2):
        bit_sum += int.from_bytes(packet[i:i + 2], byteorder='big')
        bit_sum &= 0xffff
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
