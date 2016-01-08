
from __future__ import print_function
import struct
from Tkinter import Tk

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def continue_sha1(mac, message, append, keysize):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        message: The input message string to hash.
    Returns:
        A hex SHA-1 digest of the input message.
    """
    # Initialize variables to the received mac:
    h0 = long(mac[:8], 16)
    h1 = long(mac[8:16], 16)
    h2 = long(mac[16:24], 16)
    h3 = long(mac[24:32], 16)
    h4 = long(mac[32:40], 16)


    # pad the original message
    original_byte_len = len(message) + keysize
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    message += struct.pack(b'>Q', original_bit_len)

    # append the new message
    message += append
    message_to_send = message  # this is the message to be sent

    # pad the result
    original_byte_len = len(message) + keysize
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    message += struct.pack(b'>Q', original_bit_len)

    for i in range(len(message)-64, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for r in range(80):
            if 0 <= r <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= r <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= r <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= r <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[r]) & 0xffffffff,
                            a, _left_rotate(b, 30), c, d)

        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return message_to_send, '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

if __name__ == '__main__':
    # Imports required for command line parsing. No need for these elsewhere
    import argparse

    # Parse the incoming arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--message', '-m', help='The original plaintext message', required=True)
    parser.add_argument('--mac', '-c', help='The original MAC', required=True)
    parser.add_argument('--append', '-a', help='The data to be appended', required=True)
    parser.add_argument('--keysize', '-s', help='The keysize of hidden key', required=True)

    args = parser.parse_args()

    print(args.message)

    new_message, new_mac = continue_sha1(args.mac, args.message, args.append, int(args.keysize))

    # Show the final digest
    print('New message: ', ("".join("{:02x}".format(ord(c)) for c in new_message)))
    print(new_message, file=open('out.txt', 'w'))
    print('New mac: ', new_mac)
