#!/usr/bin/env python3

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
    print("Received %d bytes" % len(data))
    crc = "[" + hex(len(data))[2:] + "|" + hex(binascii.crc32(data))[2:] + "]\n"
    sock.sendto(crc.encode('ascii'), addr)
