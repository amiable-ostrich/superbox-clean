#!/usr/bin/env python3
"""Send an unsigned ADB handshake. AUTH means a challenge, not a full security audit."""
import argparse
import socket
import struct
from superbox import device_arg

def probe(endpoint):
    endpoint = device_arg(endpoint)
    if ':' not in endpoint:
        raise ValueError('Use a private IPv4:port endpoint')
    host, port = endpoint.rsplit(':', 1)
    body = b'host::\0'
    command = int.from_bytes(b'CNXN', 'little')
    packet = struct.pack('<6I', command, 0x01000000, 4096, len(body), sum(body), command ^ 0xffffffff) + body
    with socket.create_connection((host, int(port)), timeout=3) as connection:
        connection.sendall(packet)
        header = b''
        while len(header) < 24:
            part = connection.recv(24 - len(header))
            if not part:
                raise ValueError('Incomplete ADB reply')
            header += part
        cmd, arg0, arg1, length, checksum, magic = struct.unpack('<6I', header)
        if magic != cmd ^ 0xffffffff or length > 1024 * 1024:
            raise ValueError('Invalid ADB reply')
        return cmd.to_bytes(4, 'little').decode('ascii')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--device', required=True)
    args = p.parse_args()
    try:
        reply = probe(args.device)
        print(reply)
        if reply != 'AUTH':
            p.exit(1, 'Expected AUTH. CNXN means unauthenticated access was accepted.\n')
    except (OSError, ValueError, argparse.ArgumentTypeError) as e:
        p.exit(1, str(e) + '\n')
