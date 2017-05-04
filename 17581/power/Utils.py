import hashlib
import binascii
import math

import numpy
from Crypto.Cipher import AES
import pickle


def AES_XTS_Check(key1, key2, i, j, c):
    key1 = HexToByte(key1)
    key2 = HexToByte(key2)
    _i = HexToByte(i)
    c = os2ip(c)

    T = AES.new(key2).encrypt(_i)
    T = os2ip(ByteToHex(T))
    # Next operation: Group multiplication with j, but j = 0. Therefore T stays the same.
    CC = c ^ T
    PP = AES.new(key1).decrypt(HexToByte(i2osp( CC )))
    PP = os2ip(ByteToHex(PP))
    P = PP ^ T
    return i2osp(P)

# Convert hex to Byte List
def HexToByteList(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string) - 1, 2)]

# Convert hex to Byte List
def ByteListToHexString(byteList):
    return "".join([("%X" % byte).zfill(2) for byte in byteList])

# Convert Byte (4 bit) string to Hex (2 bit) string
def ByteToHex(byte_string) :
    if len(byte_string) <= 16:
        return binascii.hexlify(byte_string).zfill(32)
    else :
        return byte_string.zfill(32)

# Convert Hex (2 bit) string to Hex (4 bit) string
def HexToByte(hex_string) :
    if len(hex_string) <= 16:
        return hex_string.zfill(16)
    else :
        return hex_string.strip().zfill(16).decode('hex').zfill(16)

# Octal String to Integer
def os2ip(X):
    if isinstance(X, ( int, long )):
        return X
    elif X == '':
        return 0
    else:
        return int(X, 16)

# Integer to Octal String
def i2osp(X):
    if isinstance(X, basestring):
        return X.zfill(32)
    else:
        return format(X, 'X').zfill(32)


# Convert to Hex string
def toHex(X):
    if isinstance(X, ( int, long )):
        return "%X\n" % X
    elif X == '':
        return 0
    else:
        return X.encode('hex')

# Multiply a(x) by x
def gf28_mulx(a):
    return (((a << 1) ^ 0x1B) if a & 0x80 else (a << 1)) & 0xFF

# Multiply a(x) by b(x)
def gf28_mul(a, b):
    t = 0
    for i in range(7, -1, -1):
        t = gf28_mulx(t)
        if (b >> i) & 1:
            t ^= a
    return t

# Utils for ATTACK

def getTrace(_traces) :
    __traces = _traces.split(',')[1:]
    traces = []
    for i in __traces:
        traces.append(int(i))
    return (traces)

def preprocessTrace(_traces):
    avg = numpy.mean(_traces)
    std = numpy.std(_traces)
    x = std
    traces = []
    for i in _traces:
        if i > x + avg or i < avg - x:
            traces.append(int(i))
    return traces

def sameLengthTraceSets(traces):
    smallest = len(traces[0])
    for t in traces:
        if len(t) < smallest:
            smallest = len(t)
    for i in range(len(traces)):
        tmp = traces[i]
        traces[i] = tmp[:smallest]
    return traces


def printComparison(newByte, i, key):
    if key == 1:
        str1 = "4BD55725A2D190A44D73764FE3EC68F7"
    else:
        str1 = "2BDC1E95C035F9520ACF58EEC0C30B88"
    ind = i * 2
    str_i = str1[ind:ind + 2]

    scale = 16  ## equals to hexadecimal
    num_of_bits = 8
    print "True:  Byte " + str(i) + " : " + bin(int(str_i, scale))[2:].zfill(num_of_bits) + " : " + str_i
    print "Guess: Byte " + str(i) + " : " + bin(int(newByte, scale))[2:].zfill(num_of_bits) + " : " + newByte


def getByte(ciphertext, index) :
    return int(ciphertext[index*2 : index*2 + 2], 16)
