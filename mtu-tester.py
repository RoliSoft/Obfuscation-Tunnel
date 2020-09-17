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

def try_send_bytes(sock, count):
    print("Trying %d bytes: " % count, flush=True, end='')
    #message = b'\x90' * count
    message = bytearray(os.urandom(count))

    try:
        sock.sendto(message, endpoint)
    except:
        print("failed to send locally")
        return False

    try:
        data, addr = sock.recvfrom(100)
        match = re.search(r'\[([0-9a-f]+)\|([0-9a-f]+)\]', data.decode('ascii'))

        if match is None:
            print("malformed data received")
            return False

        rcount = int(match.group(1), 16)
        if rcount != count:
            print("incorrect size received from server (%d diff)" % (rcount - count))
            return False

        if int(match.group(2), 16) != binascii.crc32(message):
            print("incorrect checksum received from server")
            return False

        print("correct data")
        return True
    except UnicodeDecodeError:
        print("malformed data received")
        return False
    except socket.timeout:
        print("failed to receive reply")
        return False

def try_recv_bytes(sock, count):
    print("Requesting %d bytes: " % count, flush=True, end='')

    try:
        sock.sendto(("[<%d>]\n" % count).encode('ascii'), endpoint)
    except:
        print("failed to request")
        return False

    try:
        data, addr = sock.recvfrom(10000)

        rcount = len(data)
        if rcount != count:
            print("incorrect size received from server (%d diff)" % (rcount - count))
            return False

        print("correct data")
        return True
    except UnicodeDecodeError:
        print("malformed data received")
        return False
    except socket.timeout:
        print("failed to receive reply")
        return False

def binary_search_mtu(sock, callback):
    low = 1
    high = 10000
    mid = 0
    while low <= high: 
        mid = (high + low) // 2

        if callback(sock, mid):
            low = mid + 1
        else:
            high = mid - 1
    
    return high

print()
mtu_up = binary_search_mtu(sock, try_send_bytes)
print()
mtu_down = binary_search_mtu(sock, try_recv_bytes)
print("\nMTU: %d upstream / %d downstream" % (mtu_up, mtu_down))
