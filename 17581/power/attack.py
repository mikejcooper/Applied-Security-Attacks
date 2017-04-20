import subprocess

import sys

import random

import numpy
from numpy import matrix, corrcoef, float32, uint8
from numpy.ma import zeros

from Utils import *

# import hashlib
# import sys, subprocess
# import sys
# import binascii
#
#
#
# ORACLE_QUERIES = 0
#
# # Expected label l and ciphertext c as octet strings
# def Interact( fault, m ) :
#     # Send (fault, message) to attack target.
#     target_in.write( "%s\n" % ( fault ) )
#     target_in.write( "%s\n" % ( i2osp(m) ) )
#     target_in.flush()
#     # From Oracle: 1-block AES ciphertext (represented as an octet string)
#     _traces = target_out.readline().strip()[:None]
#
#     if _traces[-1] == ',' or _traces[-1] == ' ':
#         _traces = _traces[:-1]
#
#     __traces = _traces.split(',')
#     traces = []
#     for i in __traces:
#         traces.append(int(i))
#     # Receive decryption from attack target
#     dec = target_out.readline().strip()
#     # return (traces, dec)
#
#
#     globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
#     return m
#
# # Expected label l and ciphertext c as octet strings
# def Interact( j, i, c, k) :
#     # Send (fault, message) to attack target.
#     target_in.write( "%s\n" % ( j ) )
#     target_in.write( "%s\n" % ( i ) )
#     target_in.write( "%s\n" % ( c ) )
#     target_in.write( "%s\n" % ( k ) )
#     target_in.flush()
#
#     # From Oracle: 1-block AES ciphertext (represented as an octet string)
#     _traces = target_out.readline()
#
#     # Receive decryption from attack target
#     dec = target_out.readline().strip()
#
#     return (_traces, dec)
#
#
# def playground():
#     print "hey"
#     #        r, f, p, i, j
#
#     # k = AES_1_Block("This is my password") + AES_1_Block("This is my password")
#     # m = AES_1_Block("hello world")
#     # c = AES.new(k).encrypt(m)
#     #
#     # k = ByteToHex256(k)
#     # c = ByteToHex(c)
#     # m = ByteToHex(m)
#
#
#
#     m = '6bc1bee22e409f96e93d7e117393172a'
#     c = '55ece01bd0b359d2f12b0a01fcab5be2'
#     k = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c'
#     j = "00"
#     i = "00000000000000000000000000000000"
#
#     (t,m_dec) = Interact(j, i, c, k)
#
#
#     if m.upper() == m_dec.upper() :
#         print "hello"
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
# # Octal String to Integer
# def os2ip(X):
#     if isinstance(X, ( int, long )):
#         return X
#     elif X == '':
#         return 0
#     else:
#         return int(X, 16)
#
# # Integer to Octal String
# def i2osp(X):
#     if isinstance(X, basestring):
#         return X
#     else:
#         return format(X, 'X')
#
#
# if ( __name__ == "__main__" ) :
#     # Produce a sub-process representing the attack target.
#     target = subprocess.Popen( args   = sys.argv[ 1 ],
#                              stdout = subprocess.PIPE,
#                              stdin  = subprocess.PIPE )
#
#     # Construct handles to attack target standard input and output.
#     target_out = target.stdout
#     target_in  = target.stdin
#
#     playground()
#
#
#
#
#


OCTET_SIZE = 32
BYTES = 16
SAMPLES = 150
CIPHERTEXTSIZE = 128
KEY_RANGE = 256
TRACE_NUM = 4000

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

inv_s = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

def SubBytes(x) :
    return sbox[x]

# def interact( plaintext ) :
#   # Send plaintext to attack target.
#   target_in.write( ("%s\n" % ( plaintext )).zfill(OCTET_SIZE) ) ; target_in.flush()
#
#   # Receive power consumption trace and ciphertext from attack target.
#   trace      = target_out.readline().strip()
#   ciphertext = int(target_out.readline().strip(), 16)
#
#   traces = getPowerTrace(trace)
#
#   return (traces, ciphertext)
#
# def getPowerTrace(trace) :
#     traces_l = trace.split(',')
#
#     length = int(traces_l[0])
#
#     traces = []
#     tadd = traces.append
#
#     for i in range(1, TRACE_NUM+1) :
#         tadd(int(traces_l[i]))
#
#     return traces



def generateRandomInputs() :
    samples = []
    # for i in range(0, SAMPLES):
    #     # generate random ciphertext
    #     sample = "%X" % random.getrandbits(CIPHERTEXTSIZE)
    #     samples.append(sample.zfill(32))
    samples = CIPHERTEXTS
    return samples

import pickle

def interactAll(inputs):
    traces = []; outputs = [];
    # for i in inputs:
    #     _traces, _output = interact(i)
    #     traces.append(_traces)
    #     outputs.append(_output)
    # storeInfo(traces)
    traces = getInfo()
    return (outputs, traces)

def storeInfo(info):
    afile = open(r'C:\d.pkl', 'wb')
    pickle.dump(info, afile)
    afile.close()

def getInfo():
    # reload object from file
    file2 = open(r'C:\d.pkl', 'rb')
    new_d = pickle.load(file2)
    file2.close()
    # print dictionary object loaded from file
    return new_d


def interact( input ) :
  j = "0"
  i = "00000000000000000000000000000000"

  k = '1BEE5A32595F3F3EA365A590028B7017' + '5B6BA73EB81D4840B21AE1DB10F61B8C'
  c = "A99CE4A0687CE8E8D1140F2EC21345EB"

  target_in.write("%s\n" % j)
  target_in.write("%s\n" % input)
  target_in.write("%s\n" % c)
  target_in.write("%s\n" % k)
  target_in.flush()

  # Receive power consumption trace and ciphertext from attack target.
  trace      = target_out.readline().strip()
  plaintext = int(target_out.readline().strip(), 16)

  traces = getTrace(trace)

  return (traces, plaintext)




# Get hypothetical intermediate values
def getIntermediateValues(byte_i, plaintexts) :

    V = zeros((len(plaintexts), KEY_RANGE), uint8)
    # For current byte, enumerate over each ciphertext and compute each possible key value
    for i, p in enumerate(plaintexts) :
        p_i = getByte(p, byte_i)

        global T

        for k in range(KEY_RANGE) :
            # Multi-bit (1 byte) DPA Attack
            V[i][k] = SubBytes(p_i ^ k)

    return V

# Calculate Hamming Weight - number of symbols different from the zero-symbol
def hammingWeight(v) :
    return bin(v).count("1")

def getHammingWeightMatrix(V) :
    H = zeros((len(V), KEY_RANGE), uint8)
    for i in range(len(V)) :
        for j in range(KEY_RANGE) :
            H[i][j] = hammingWeight(V[i][j])

    return H

def attackByte(byte_i, plaintexts, traces) :
    # Get hypothetical intermediate values
    IV = getIntermediateValues(byte_i, plaintexts)
    # Power Consumption hypothetical
    PC_h = getHammingWeightMatrix(IV).transpose()
    # Power Consumption actual
    PC_a = matrix(traces).transpose()

    len_PC_a = len(PC_a)

    CC = zeros((KEY_RANGE, TRACE_NUM), float32)

    # Compute the correlation
    # For each hypothetical, For each actual
    for i in range(0, KEY_RANGE) :
        for j in range(0, TRACE_NUM) :
            traceIndex = random.randint(0, len_PC_a - 1)
            # Correlation matrix
            list1 = PC_h[i]
            list2 = PC_a[j]
            CC[i][j] = corrcoef( PC_h[i], PC_a[j] )[0][1]
    return CC


def generateSamples():
    # Generate samples
    print "Generating %d samples..." % SAMPLES

    inputs = generateRandomInputs()
    outputs, traces = interactAll(inputs)

    return (inputs, outputs, traces)

def attack1(inputs, outputs, traces) :
    global TRACE_NUM


    print "Attacking key using the first %d data points from each trace for each sample" % TRACE_NUM

    key = ""
    for i in range(0, BYTES):
        print "\n Attacking %d Byte..." % i
        R = attackByte(i, inputs, traces)
        max_coeff = R[0].max()
        keyByte = 0
        # Find the value in (0, 255) with the highest correlation coefficient.
        for k in range(1,KEY_RANGE):
            current_coeff = R[k].max()
            # If current coefficient value is larger (current k is more likely)
            if current_coeff > max_coeff :
                max_coeff = current_coeff
                keyByte = k
        newByte = ("%X" % keyByte).zfill(2)
        key += newByte
        printComparison(newByte,i, 0)
    return key


def attack2(inputs, outputs, traces) :
    print "Attacking key using the first %d data points from each trace for each sample" % TRACE_NUM

    

    key = ""
    for i in range(0, BYTES):
        print "\n Attacking %d Byte..." % i
        R = attackByte(i, outputs, traces)
        max_coeff = R[0].max()
        keyByte = 0
        # Find the value in (0, 255) with the highest correlation coefficient.
        for k in range(1,KEY_RANGE):
            current_coeff = R[k].max()
            # If current coefficient value is larger (current k is more likely)
            if current_coeff > max_coeff :
                max_coeff = current_coeff
                keyByte = k
        newByte = ("%X" % keyByte).zfill(2)
        key += newByte
        printComparison(newByte,i, 255)
    return key

if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    inputs, outputs, traces = generateSamples()
    # Execute a function representing the attacker.
    # Attack key 2
    key2 = attack1(inputs, outputs, traces)
    # Attack key 1
    key1 = attack2(inputs, outputs, traces)

    print "\nGuess: key: " + key1 + key2
    print "True : Key: " + "1BEE5A32595F3F3EA365A590028B7017" + "5B6BA73EB81D4840B21AE1DB10F61B8C"






# Byte 0      : 61
# Byte 1      : A4
# Byte 2      : C1
# Byte 3      : 40

    # recovered_key = "61A4C140DD7409B8066A36F92AEF097A"




