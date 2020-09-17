#!/usr/bin/env python3

import os
import re
import sys
import socket
import binascii

if len(sys.argv) < 2:
    print("usage: %s port" % sys.argv[0])
    exit()

endpoint = ("0.0.0.0", int(sys.argv[1]))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(endpoint)

print("Listening at", endpoint)

while True:
    data, addr = sock.recvfrom(10000)
    print("Received %d bytes: " % len(data), end='')

    send = 0

    try:
        match = re.search(r'^\[<([0-9a-f]+)>\]$', data.decode('ascii'))
        if match is not None:
            send = int(match.group(1))
            if send > 10000:
                send = 10000
    except:
        pass

    if send == 0:
        print("sending checksum")
        crc = "[" + hex(len(data))[2:] + "|" + hex(binascii.crc32(data))[2:] + "]\n"
        sock.sendto(crc.encode('ascii'), addr)
    else:
        print("sending %d requested bytes" % send)
        message = bytearray(os.urandom(send))
        try:
            sock.sendto(message, addr)
        except:
            pass
