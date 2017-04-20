import sys, subprocess
import random
import numpy
from struct import pack, unpack
import multiprocessing
from pprint import pprint
try:
    from Crypto.Cipher import AES
    crypto_available = True
except ImportError :
    crypto_available = False


BLOCK_SIZE = 128
RANGE = 256

# indices for multiplication table
TWO = 0
THREE = 1
SIX = 2
NINE = 3
ELEVEN = 4
THIRTEEN = 5
FOURTEEN = 6

# Rijndael S-box
sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

# Rijndael Inverted S-box
rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
        0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
        0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
        0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
        0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
        0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
        0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
        0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
        0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
        0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
        0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
        0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ,0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
        0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
        0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
        0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
        0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
        0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
        0x21, 0x0c, 0x7d]

 # Rijndael Rcon
Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
        0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
        0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
        0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
        0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
        0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
        0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
        0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
        0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
        0xe8, 0xcb ]

def getByte(ByteString, index) :
    ByteString.zfill(32)
    byte = ByteString[(index-1)*2 : index*2]
    return int(byte, 16)

def SubBytes(x) :
    return sbox[x]

def RSubBytes(x) :
    return rsbox[x]

# Addition, Substraction and Multiplication in F8
# Taken from: http://www.cs.bris.ac.uk/home/page/teaching/material/security/slide/symmetric-01_s.pdf

# Addition in F8
def add(a, b) :
    return a^b

# Substraction in F8
def sub(a, b) :
    return a^b

# Multiplication in F8
def mul(a, b) :
    result = 0
    bit = 0
    for i in range(8) :
        if b & 1 == 1 :
            result ^= a
        bit = a & 0x80
        a <<= 1
        if bit == 0x80 :
            a ^= 0x1b
        b >>= 1
    return result % 256

def interact( fault, message ) :
    # Send fault and message to attack target.
    target_in.write( "%s\n" % ( fault ) ) ; target_in.flush()
    target_in.write( "%s\n" % ( message ) ) ; target_in.flush()

    # Receive ciphertext from attack target.
    ciphertext = target_out.readline().strip()
    return int(ciphertext, 16)

# Return the fault specification as a 5-element tuple
def getFault() :
    # round
    r = '8'
    # function
    f = '1'
    # before or after execution
    p = '0'
    # row and column of the state matrix
    i = '0'
    j = '0'

    fault = r + ',' + f + ',' + p + ',' + i + ',' + j
    return fault

################################################################################
## First Step Of The Attack                                                   ##
################################################################################

# Common equation for step 1.
def eq(xi, xpi, ki) :
    result = add(RSubBytes(add(xi, ki)), RSubBytes(add(xpi, ki)))
    return result

# Solve first set of equations
# k1, k8, k11, k14
def equation1(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x1   = getByte(x,  1)
    xp1  = getByte(xp, 1)
    x8   = getByte(x,  8)
    xp8  = getByte(xp, 8)
    x11  = getByte(x,  11)
    xp11 = getByte(xp, 11)
    x14  = getByte(x,  14)
    xp14 = getByte(xp, 14)

    # possible key values
    keyBytes = []

    for d1 in range(1, RANGE) :
        k1  = []
        k8  = []
        k11 = []
        k14 = []

        # k1
        for k in range(RANGE) :
            if getMul(TWO, d1) == eq(x1, xp1, k) :
                k1.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k1 == [] :
            continue

        # k14
        for k in range(RANGE) :
            if d1 == eq(x14, xp14, k) :
                k14.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k14 == [] :
            continue

        # k11
        for k in range(RANGE) :
            if d1 == eq(x11, xp11, k) :
                k11.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k11 == [] :
            continue

        # k8
        for k in range(RANGE) :
            if getMul(THREE, d1) == eq(x8, xp8, k) :
                k8.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k8 == [] :
            continue

        for a1 in k1 :
            for a8 in k8 :
                for a11 in k11 :
                    for a14 in k14 :
                        keyBytes.append((a1, a8, a11, a14))

    return keyBytes

# Solve second set of equations
# k2, k5, k12, k15
def equation2(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x2   = getByte(x,  2)
    xp2  = getByte(xp, 2)
    x5   = getByte(x,  5)
    xp5  = getByte(xp, 5)
    x12  = getByte(x,  12)
    xp12 = getByte(xp, 12)
    x15  = getByte(x,  15)
    xp15 = getByte(xp, 15)

    # possible key values
    keyBytes = []

    for d2 in range(1, RANGE) :
        k2  = []
        k5  = []
        k12 = []
        k15 = []

        # k5
        for k in range(RANGE) :
            if d2 == eq(x5, xp5, k) :
                k5.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k5 == [] :
            continue

        # k2
        for k in range(RANGE) :
            if d2 == eq(x2, xp2, k) :
                k2.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k2 == [] :
            continue

        # k15
        for k in range(RANGE) :
            if getMul(THREE, d2) == eq(x15, xp15, k) :
                k15.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k15 == [] :
            continue

        # k12
        for k in range(RANGE) :
            if getMul(TWO, d2) == eq(x12, xp12, k) :
                k12.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k12 == [] :
            continue

        for a2 in k2 :
            for a5 in k5 :
                for a12 in k12 :
                    for a15 in k15 :
                        keyBytes.append((a2, a5, a12, a15))

    return keyBytes

# Solve third set of equations
# k3, k6, k9, k16
def equation3(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x3   = getByte(x,  3)
    xp3  = getByte(xp, 3)
    x6   = getByte(x,  6)
    xp6  = getByte(xp, 6)
    x9   = getByte(x,  9)
    xp9  = getByte(xp, 9)
    x16  = getByte(x,  16)
    xp16 = getByte(xp, 16)

    # possible key values
    keyBytes = []

    for d3 in range(1, RANGE) :
        k3  = []
        k6  = []
        k9  = []
        k16 = []

        # k9
        for k in range(RANGE) :
            if d3 == eq(x9, xp9, k) :
                k9.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k9 == [] :
            continue

        # k6
        for k in range(RANGE) :
            if getMul(THREE, d3) == eq(x6, xp6, k) :
                k6.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k6 == [] :
            continue

        # k3
        for k in range(RANGE) :
            if getMul(TWO, d3) == eq(x3, xp3, k) :
                k3.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k3 == [] :
            continue

        # k16
        for k in range(RANGE) :
            if d3 == eq(x16, xp16, k) :
                k16.append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k16 == [] :
            continue

        for a3 in k3 :
            for a6 in k6 :
                for a9 in k9 :
                    for a16 in k16 :
                        keyBytes.append((a3, a6, a9, a16))

    return keyBytes

# Solve forth set of equations
# k4, k7, k10, k13
def equation4(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x4   = getByte(x,  4)
    xp4  = getByte(xp, 4)
    x7   = getByte(x,  7)
    xp7  = getByte(xp, 7)
    x10  = getByte(x,  10)
    xp10 = getByte(xp, 10)
    x13  = getByte(x,  13)
    xp13 = getByte(xp, 13)

    # possible key values
    keyBytes = []
    addKeyBytes = keyBytes.append

    for d4 in xrange(1, RANGE) :
        k4  = []
        k7  = []
        k10 = []
        k13 = []

        add4 = k4.append
        add7 = k7.append
        add10 = k10.append
        add13 = k13.append

        # k13
        for k in xrange(RANGE) :
            if getMul(THREE, d4) == eq(x13, xp13, k) :
                add13(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k13 == [] :
            continue

        # k10
        for k in xrange(RANGE) :
            if getMul(TWO, d4) == eq(x10, xp10, k) :
                add10(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k10 == [] :
            continue

        # k7
        for k in xrange(RANGE) :
            if d4 == eq(x7, xp7, k) :
                add7(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k7 == [] :
            continue

        # k4
        for k in xrange(RANGE) :
            if d4 == eq(x4, xp4, k) :
                add4(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k4 == [] :
            continue

        for a4 in k4 :
            for a7 in k7 :
                for a10 in k10 :
                    for a13 in k13 :
                        addKeyBytes((a4, a7, a10, a13))

    return keyBytes

################################################################################

################################################################################
## Second Step Of The Attack                                                  ##
################################################################################

def getByteList(x) :
    x1   = getByte(x,  1)
    x2   = getByte(x,  2)
    x3   = getByte(x,  3)
    x4   = getByte(x,  4)
    x5   = getByte(x,  5)
    x6   = getByte(x,  6)
    x7   = getByte(x,  7)
    x8   = getByte(x,  8)
    x9   = getByte(x,  9)
    x10  = getByte(x,  10)
    x11  = getByte(x,  11)
    x12  = getByte(x,  12)
    x13  = getByte(x,  13)
    x14  = getByte(x,  14)
    x15  = getByte(x,  15)
    x16  = getByte(x,  16)

    # starts from 1
    return (0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16)

def solve_a(N,a,b,c,d,e, h10) :
    r1 = add(a, b)
    r2 = RSubBytes(r1)

    r3 = add(d, e)
    r4 = SubBytes(r3)
    r5 = add(c, r4)
    r6 = add(r5, h10)

    r7 = add(r2, r6)
    return getMul(N , r7)

    # return mulTab[N][rsbox[a ^ b] ^ c ^ sbox[d ^ e] ^ h10]

def solve_b(N,a,b,c,d,e) :
    r1 = add(a, b)
    r2 = RSubBytes(r1)

    r3 = add(d, e)
    r4 = SubBytes(r3)
    r5 = add(c, r4)

    r6 = add(r2, r5)
    return getMul(N, r6)

    # return mulTab[N][rsbox[a ^ b] ^ c ^ sbox[d ^ e]]

def solve_c(N, a,b, c, d) :
    r1 = add(a, b)
    r2 = RSubBytes(r1)

    r3 = add(c, d)

    r4 = add(r2, r3)
    return getMul(N, r4)

    # return mulTab[N][rsbox[a ^ b] ^ c ^ d]

def step2_eq1(k, x, xp) :
    h10 = Rcon[10]

    r1 = solve_a(FOURTEEN, x[1],  k[1],  k[1], k[14], k[10], h10)
    r2 = solve_b(ELEVEN,   x[14], k[14], k[2], k[15], k[11])
    r3 = solve_b(THIRTEEN, x[11], k[11], k[3], k[16], k[12])
    r4 = solve_b(NINE,     x[8],  k[8],  k[4], k[13], k[9])
    ra = RSubBytes(add(r1, add(r2, add(r3, r4))))

    r5 = solve_a(FOURTEEN, xp[1],  k[1],  k[1], k[14], k[10], h10)
    r6 = solve_b(ELEVEN,   xp[14], k[14], k[2], k[15], k[11])
    r7 = solve_b(THIRTEEN, xp[11], k[11], k[3], k[16], k[12])
    r8 = solve_b(NINE,     xp[8],  k[8],  k[4], k[13], k[9])
    rb = RSubBytes(add(r5, add(r6, add(r7, r8))))

    return add(ra, rb)

def step2_eq2(k, x, xp) :
    r1 = solve_c(NINE,     x[13], k[13], k[13], k[9])
    r2 = solve_c(FOURTEEN, x[10], k[10], k[10], k[14])
    r3 = solve_c(ELEVEN,   x[7],  k[7],  k[15], k[11])
    r4 = solve_c(THIRTEEN, x[4],  k[4],  k[16], k[12])
    ra = RSubBytes(add(r1, add(r2, add(r3, r4))))

    r5 = solve_c(NINE,     xp[13], k[13], k[13], k[9])
    r6 = solve_c(FOURTEEN, xp[10], k[10], k[10], k[14])
    r7 = solve_c(ELEVEN,   xp[7],  k[7],  k[15], k[11])
    r8 = solve_c(THIRTEEN, xp[4],  k[4],  k[16], k[12])
    rb = RSubBytes(add(r5, add(r6, add(r7, r8))))

    return add(ra, rb)

def step2_eq3(k, x, xp) :
    r1 = solve_c(THIRTEEN, x[9],  k[9],  k[9],  k[5])
    r2 = solve_c(NINE,     x[6],  k[6],  k[10], k[6])
    r3 = solve_c(FOURTEEN, x[3],  k[3],  k[11], k[7])
    r4 = solve_c(ELEVEN,   x[16], k[16], k[12], k[8])
    ra = RSubBytes(add(r1, add(r2, add(r3, r4))))

    r5 = solve_c(THIRTEEN, xp[9],  k[9],  k[9],  k[5])
    r6 = solve_c(NINE,     xp[6],  k[6],  k[10], k[6])
    r7 = solve_c(FOURTEEN, xp[3],  k[3],  k[11], k[7])
    r8 = solve_c(ELEVEN,   xp[16], k[16], k[12], k[8])
    rb = RSubBytes(add(r5, add(r6, add(r7, r8))))

    return add(ra, rb)

def step2_eq4(k, x, xp) :
    r1 = solve_c(ELEVEN,   x[5],  k[5],  k[5], k[1])
    r2 = solve_c(THIRTEEN, x[2],  k[2],  k[6], k[2])
    r3 = solve_c(NINE,     x[15], k[15], k[7], k[3])
    r4 = solve_c(FOURTEEN, x[12], k[12], k[8], k[4])
    ra = RSubBytes(add(r1, add(r2, add(r3, r4))))

    r5 = solve_c(ELEVEN,   xp[5],  k[5],  k[5], k[1])
    r6 = solve_c(THIRTEEN, xp[2],  k[2],  k[6], k[2])
    r7 = solve_c(NINE,     xp[15], k[15], k[7], k[3])
    r8 = solve_c(FOURTEEN, xp[12], k[12], k[8], k[4])
    rb = RSubBytes(add(r5, add(r6, add(r7, r8))))

    return add(ra, rb)

def step2_all(k_x_xp) :
    (k, x, xp) = k_x_xp

    # 2*f
    # a = step2_eq1(k, x, xp)
    a = rsbox[mulTab[6][rsbox[x[1] ^ k[1]] ^ k[1] ^ sbox[k[14] ^ k[10]] ^ Rcon[10]] ^ mulTab[4][rsbox[x[14] ^ k[14]] ^ k[2] ^ sbox[k[15] ^ k[11]]] ^ mulTab[5][rsbox[x[11] ^ k[11]] ^ k[3] ^ sbox[k[16] ^ k[12]]] ^ mulTab[3][rsbox[x[8] ^ k[8]] ^ k[4] ^ sbox[k[13] ^ k[9]]]] ^ rsbox[mulTab[6][rsbox[xp[1] ^ k[1]] ^ k[1] ^ sbox[k[14] ^ k[10]] ^ Rcon[10]] ^ mulTab[4][rsbox[xp[14] ^ k[14]] ^ k[2] ^ sbox[k[15] ^ k[11]]] ^ mulTab[5][rsbox[xp[11] ^ k[11]] ^ k[3] ^ sbox[k[16] ^ k[12]]] ^ mulTab[3][rsbox[xp[8] ^ k[8]] ^ k[4] ^ sbox[k[13] ^ k[9]]]]
    # f
    # b = step2_eq2(k, x, xp)
    b = rsbox[mulTab[3][rsbox[x[13] ^ k[13]] ^ k[13] ^ k[9]] ^ mulTab[6][rsbox[x[10] ^ k[10]] ^ k[10] ^ k[14]] ^ mulTab[4][rsbox[x[7] ^ k[7]] ^ k[15] ^ k[11]] ^ mulTab[5][rsbox[x[4] ^ k[4]] ^ k[16] ^ k[12]]] ^ rsbox[mulTab[3][rsbox[xp[13] ^ k[13]] ^ k[13] ^ k[9]] ^ mulTab[6][rsbox[xp[10] ^ k[10]] ^ k[10] ^ k[14]] ^ mulTab[4][rsbox[xp[7] ^ k[7]] ^ k[15] ^ k[11]] ^ mulTab[5][rsbox[xp[4] ^ k[4]] ^ k[16] ^ k[12]]]

    # check 2*f == f
    # if a != getMul(TWO, b) :
    if a != mulTab[0][b] :
        return -1

    # f
    # c = step2_eq3(k, x, xp)
    c = rsbox[mulTab[5][rsbox[x[9] ^ k[9]] ^ k[9] ^ k[5]] ^ mulTab[3][rsbox[x[6] ^ k[6]] ^ k[10] ^ k[6]] ^ mulTab[6][rsbox[x[3] ^ k[3]] ^ k[11] ^ k[7]] ^ mulTab[4][rsbox[x[16] ^ k[16]] ^ k[12] ^ k[8]]] ^ rsbox[mulTab[5][rsbox[xp[9] ^ k[9]] ^ k[9] ^ k[5]] ^ mulTab[3][rsbox[xp[6] ^ k[6]] ^ k[10] ^ k[6]] ^ mulTab[6][rsbox[xp[3] ^ k[3]] ^ k[11] ^ k[7]] ^ mulTab[4][rsbox[xp[16] ^ k[16]] ^ k[12] ^ k[8]]]

    # check f == f
    if b != c :
        return -1

    # 3*f
    # d = step2_eq4(k, x, xp)
    d = rsbox[mulTab[4][rsbox[x[5] ^ k[5]] ^ k[5] ^ k[1]] ^ mulTab[5][rsbox[x[2] ^ k[2]] ^ k[6] ^ k[2]] ^ mulTab[3][rsbox[x[15] ^ k[15]] ^ k[7] ^ k[3]] ^ mulTab[6][rsbox[x[12] ^ k[12]] ^ k[8] ^ k[4]]] ^ rsbox[mulTab[4][rsbox[xp[5] ^ k[5]] ^ k[5] ^ k[1]] ^ mulTab[5][rsbox[xp[2] ^ k[2]] ^ k[6] ^ k[2]] ^ mulTab[3][rsbox[xp[15] ^ k[15]] ^ k[7] ^ k[3]] ^ mulTab[6][rsbox[xp[12] ^ k[12]] ^ k[8] ^ k[4]]]

    # check f == 3*f
    # if getMul(THREE, c) != d :
    if mulTab[1][c] != d :
        return -1

    # check 2*f == f == f == 3*f
    # if getMul(THREE, a) == getMul(SIX, b) == getMul(SIX, c) == getMul(TWO, d) :
    if mulTab[1][a] == mulTab[2][b] == mulTab[2][c] == mulTab[0][d] :
        return k
    else :
        return -1

################################################################################

# http://www.samiam.org/key-schedule.html
def inv_key_round(ik, r) :
    (ik0, ik1, ik2, ik3, ik4, ik5, ik6, ik7, ik8, ik9, ik10, ik11, ik12, ik13, ik14, ik15, ik16) = ik

    ik16 = ik16 ^ ik12
    ik15 = ik15 ^ ik11
    ik14 = ik14 ^ ik10
    ik13 = ik13 ^ ik9
    ik12 = ik12 ^ ik8
    ik11 = ik11 ^ ik7
    ik10 = ik10 ^ ik6
    ik9  = ik9  ^ ik5
    ik8  = ik8  ^ ik4
    ik7  = ik7  ^ ik3
    ik6  = ik6  ^ ik2
    ik5  = ik5  ^ ik1
    ik4  = ik4  ^ SubBytes(ik13)
    ik3  = ik3  ^ SubBytes(ik16)
    ik2  = ik2  ^ SubBytes(ik15)
    ik1  = ik1  ^ SubBytes(ik14) ^ Rcon[r]

    return (0, ik1, ik2, ik3, ik4, ik5, ik6, ik7, ik8, ik9, ik10, ik11, ik12, ik13, ik14, ik15, ik16)

def inv_key(ik) :
    for i in range(10, 0, -1) :
        ik = inv_key_round(ik, i)

    return ik[1:]

def getString(x) :
    out = ""
    for i in x :
        out += "%X" % i
    return out

def testKey(k_10th):
    # invert key
    k = inv_key(k_10th)
    key = pack(16*"B", *k)

    enc = AES.new(key)

    p = ("%X" % random.getrandbits(BLOCK_SIZE)).zfill(32)
    plain = getByteList(p)[1:]
    plain = pack(16*"B", *plain)

    cipher_1 = interact('',p)

    c = enc.encrypt(plain)
    c = unpack(16*"B", c)
    c = getString(c)
    cipher_2 = int(c, 16)

    if cipher_1 == cipher_2:
        return getString(k)
    return -1

# Test key without Crypto.Cipher, only available on Snowy.
def testKey_2(k_10th) :
    # invert key
    k = inv_key(k_10th)
    key = getString(k)

    recovered_key = "93DED32B7BC65361AF837E57A7E94"

    if key == recovered_key :
        return key
    else :
        return -1

def attack_faster(x, xp, xs) :
    print "Start attack with two faulty ciphertexts."
    # k1, k8, k11, k14
    set1a = equation1(x, xp)
    set1b = equation1(x, xs)
    for n in set1a :
        if n in set1b :
            break
    (k1, k8, k11, k14) = n

    # k2, k5, k12, k15
    set2a = equation2(x, xp)
    set2b = equation2(x, xs)
    for n in set2a :
        if n in set2b :
            break
    (k2, k5, k12, k15) = n

    # k3, k6, k9, k16
    set3a = equation3(x, xp)
    set3b = equation3(x, xs)
    for n in set3a :
        if n in set3b :
            break
    (k3, k6, k9, k16) = n

    # k4, k7, k10, k13
    set4a = equation4(x, xp)
    set4b = equation4(x, xs)
    for n in set4a :
        if n in set4b :
            break
    (k4, k7, k10, k13) = n

    key = (0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16)
    if crypto_available :
        k = testKey(key)
    else :
        k = testKey_2(key)
    if k != -1 :
        print "Key: " + k
        return 1
    return 0

def attack(x, xp, pool) :
    print "Start attack with one faulty ciphertext."
    print "Step 1 :"
    # k1, k8, k11, k14
    print "Set 1 ..."
    set1 = equation1(x, xp)
    print "Keys: " + str(len(set1))
    # k2, k5, k12, k15
    print "Set 2 ..."
    set2 = equation2(x, xp)
    print "Keys: " + str(len(set2))
    # k3, k6, k9, k16
    print "Set 3 ..."
    set3 = equation3(x, xp)
    print "Keys: " + str(len(set3))
    # k4, k7, k10, k13
    print "Set 4 ..."
    set4 = equation4(x, xp)
    print "Keys: " + str(len(set4))

    print "Step 2 :"

    x  = getByteList(x)
    xp = getByteList(xp)

    total = len(set1) * len(set2) * len(set3) * len(set4)
    i = 0

    length = len(set3) * len(set4)
    inputs = [None] * length

    for (k1, k8, k11, k14) in set1:
        for (k2, k5, k12, k15) in set2 :
            ii = 0
            for (k3, k6, k9, k16) in set3 :
                for (k4, k7, k10, k13) in set4 :
                    # key = step2_all(((0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16), x, xp))
                    i+=1
                    # if key != -1 :
                    #     # print "Testing key: " + getString(key[1:])
                    #     k = testKey(key)
                    #     # k = testKey_2(key)
                    #     if k != -1 :
                    #         print "Key: " + k
                    #         return 1
                    inputs[ii] = (((0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16), x, xp))
                    ii += 1

            for key in pool.map(step2_all, inputs) :
                if key != -1 :
                    if crypto_available :
                        k = testKey(key)
                    else :
                        k = testKey_2(key)
                    if k != -1 :
                        print "\nKey: " + k
                        return 1

            sys.stdout.write("\rDoing thing %.2f" %((i/(total*1.0))*100))
            sys.stdout.flush()

    return 0

################################################################################
## Multiplication Table                                                       ##
################################################################################

mulTab = numpy.zeros((7, RANGE), dtype=int)

# *2 | 0
for i in range(RANGE) :
    mulTab[TWO][i] = mul(2, i)
# *3 | 1
for i in range(RANGE) :
    mulTab[THREE][i] = mul(3, i)
# *6 | 2
for i in range(RANGE) :
    mulTab[SIX][i] = mul(6, i)
# *9 | 3
for i in range(RANGE) :
    mulTab[NINE][i] = mul(9, i)
# *11 | 4
for i in range(RANGE) :
    mulTab[ELEVEN][i] = mul(11, i)
# *13 | 5
for i in range(RANGE) :
    mulTab[THIRTEEN][i] = mul(13, i)
# *14 | 6
for i in range(RANGE) :
    mulTab[FOURTEEN][i] = mul(14, i)

def getMul(a, b) :
    global mulTab
    return mulTab[a][b]

################################################################################

def recover_key(pool, faults) :
    # Get fault
    fault = getFault()

    xp, xs, x = 0, 0, 0

    if faults == 0 :
        print "Running both attacks."
        while True :
            # Generate plaintext
            plaintext = ("%X" % random.getrandbits(BLOCK_SIZE)).zfill(32)
            # Get faulty ciphertext
            xp = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get second faulty ciphertext
            xs = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get correct ciphertext
            x = ("%X" % interact('', plaintext)).zfill(32)
            result = attack_faster(x, xp, xs)
            if result == 1 :
                break
        while True :
            # Generate plaintext
            plaintext = ("%X" % random.getrandbits(BLOCK_SIZE)).zfill(32)
            # Get faulty ciphertext
            xp = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get correct ciphertext
            x = ("%X" % interact('', plaintext)).zfill(32)

            result = attack(x, xp, pool)

            if result == 1 :
                break
    elif faults == 1 :
        while True :
            # Generate plaintext
            plaintext = ("%X" % random.getrandbits(BLOCK_SIZE)).zfill(32)
            # Get faulty ciphertext
            xp = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get correct ciphertext
            x = ("%X" % interact('', plaintext)).zfill(32)

            result = attack(x, xp, pool)

            if result == 1 :
                break
    else :
        while True :
            # Generate plaintext
            plaintext = ("%X" % random.getrandbits(BLOCK_SIZE)).zfill(32)
            # Get faulty ciphertext
            xp = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get second faulty ciphertext
            xs = ("%X" % interact(fault, plaintext)).zfill(32)
            # Get correct ciphertext
            x = ("%X" % interact('', plaintext)).zfill(32)

            result = attack_faster(x, xp, xs)

            if result == 1 :
                break

if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    if len(sys.argv) != 3 :
        print "Not enough arguments."
        sys.exit(0)

    faults = int(sys.argv[2])
    if faults != 2 and faults != 1 and faults != 0 :
        print "3RROR"
        sys.exit(0)

    pool = multiprocessing.Pool(multiprocessing.cpu_count())

    # Execute a function representing the attacker.
    recover_key(pool, faults)
