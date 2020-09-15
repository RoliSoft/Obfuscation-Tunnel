#!/usr/bin/env python3

import os
import re
import sys
import socket
import binascii

if len(sys.argv) < 3:
    print("usage: %s host port" % sys.argv[0])
    exit()

endpoint = (sys.argv[1], int(sys.argv[2]))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)

print("Testing with endpoint at", endpoint)

def try_bytes(sock, count):
    print("Trying %d bytes: " % count, flush=True, end='')
    #message = b'\x90' * count
    message = bytearray(os.urandom(count))

    try:
        sock.sendto(message, endpoint)
    except:
        print("failed to send locally")
        return False

    try:
        data, addr = sock.recvfrom(1024)
        match = re.search(r'\[([0-9a-f]+)\|([0-9a-f]+)\]', data.decode('ascii'))

        if match is None:
            print("malformed data received")
            return False

        if int(match.group(1), 16) != count:
            print("incorrect size received from server")
            return False

        if int(match.group(2), 16) != binascii.crc32(message):
            print("incorrect checksum received from server")
            return False

        print("correct data")
        return True
    except socket.timeout:
        print("failed to receive reply")
        return False

low = 1
high = 10000
mid = 0
while low <= high: 
    mid = (high + low) // 2

    if try_bytes(sock, mid):
        low = mid + 1
    else:
        high = mid - 1

print("MTU:", high)
