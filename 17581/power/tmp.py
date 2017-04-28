import multiprocessing
import subprocess
import sys
import random

from numpy import ctypeslib

import time
from numpy import matrix, corrcoef, float32, uint8
from numpy.ma import zeros
import Queue
import threading
import urllib2
from multiprocessing.dummy import Pool as ThreadPool


from Utils import *



OCTET_SIZE = 32
BYTES = 16
SAMPLES = 150
CIPHERTEXTSIZE = 128
KEY_RANGE = 256
TRACE_NUM = 1600
TWEAKS = []

# Rijndael S-box
s = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
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

# Inverses the whole key from the tenth round
def inv_key(k):
    for i in range(10, 0, -1):
        k[4:] = \
            [
                k[0] ^ k[4],  k[1] ^ k[5],  k[2]  ^ k[6],  k[3]  ^ k[7],
                k[4] ^ k[8],  k[5] ^ k[9],  k[6]  ^ k[10], k[7]  ^ k[11],
                k[8] ^ k[12], k[9] ^ k[13], k[10] ^ k[14], k[11] ^ k[15]
            ]

        k[1:4] = [ s[k[14]] ^ k[1], s[k[15]] ^ k[2], s[k[12]] ^ k[3] ]

        k[0]   =   s[k[13]] ^ k[0] ^ r_con[i]
    return k

# 2D array to correctly ordered 1D array
def reconstruct_key(k):
    return \
    [
        k[0][0], k[1][1], k[2][2], k[3][3],
        k[1][0], k[2][1], k[3][2], k[0][3],
        k[2][0], k[3][1], k[0][2], k[1][3],
        k[3][0], k[0][1], k[1][2], k[2][3],
    ]

def SubBytes(x):
    return s[x]

def generateRandomInputs() :
    samples = []
    for i in range(0, SAMPLES):
        sample = "%X" % random.getrandbits(CIPHERTEXTSIZE)
        samples.append(sample.zfill(32))
    return samples

def interactAll(inputs):
    traces = []; outputs = [];
    for i in inputs:
        _traces, _output = interact(i)
        traces.append(_traces)
        outputs.append(_output)
    return (outputs, traces)


def generateSamples(inputs):
    # Generate samples
    print "Generating %d samples..." % SAMPLES

    outputs, traces = interactAll(inputs)

    return (outputs, traces)

def generateTweakValues(inputs, key):
    for i in inputs:
        TWEAKS.append(calculateTweak(i, key))

def calculateTweak(i, key2):
    T = AES.new(key2).encrypt(HexToByte(i))
    T = os2ip(ByteToHex(T))
    # Next operation: Group multiplication with j, but j = 0. Therefore T stays the same.
    return i2osp(T)

def interact(input):
    j = "000"
    # i = "00000000000000000000000000000000"
    k = '1BEE5A32595F3F3EA365A590028B7017' + '5B6BA73EB81D4840B21AE1DB10F61B8C'
    c = "A99CE4A0687CE8E8D1140F2EC21345EB"

    target_in.write("%s\n" % j)
    target_in.write("%s\n" % input)
    target_in.write("%s\n" % c)
    target_in.write("%s\n" % k)
    target_in.flush()

    # Receive power consumption trace and ciphertext from attack target.
    trace = target_out.readline().strip()
    plaintext = target_out.readline().strip().zfill(32)

    # plaintext_check = check("1BEE5A32595F3F3EA365A590028B7017", "5B6BA73EB81D4840B21AE1DB10F61B8C",input,0,c)




    traces = getTrace(trace)
    return (traces, plaintext)

def check(key1, key2, i, j, c):
    key1 = HexToByte(key1)
    key2 = HexToByte(key2)
    _i = HexToByte(i)
    c = os2ip(c)

    # Checks
    os = "1BEE5A32595F3F3EA365A590028B7017"
    os2ip1 = os2ip(os)
    i2osp1 = i2osp(os2ip1).upper()

    hex = "1BEE5A32595F3F3EA365A590028B7017"
    h1 = HexToByte(hex)
    b1 = ByteToHex(h1).upper()

    aes1 = AES.new(key1).encrypt(_i)
    aes2 = AES.new(key1).decrypt(aes1)
    aes2 = ByteToHex(aes2).upper()

    if(hex == b1):
        print "Hex2Byte works"
    if(os == i2osp1):
        print "i2os works"
    if (aes2 == i):
        print "AES works"



    T = AES.new(key2).encrypt(_i)
    T = os2ip(ByteToHex(T))
    # Next operation: Group multiplication with j, but j = 0. Therefore T stays the same.
    CC = c ^ T
    PP = AES.new(key1).decrypt(HexToByte(i2osp( CC )))
    PP = os2ip(ByteToHex(PP))
    P = PP ^ T
    return i2osp(P)

# Get hypothetical intermediate values
def getIntermediateValues(byte_i, plaintexts, attackType):
    V = zeros((len(plaintexts), KEY_RANGE), uint8)
    # For current byte, enumerate over each ciphertext and compute each possible key value
    for i, p in enumerate(plaintexts):
        p_i = getByte(p, byte_i)
        t_i = 0 if attackType == 2 else getByte(TWEAKS[i], byte_i)

        for k in range(KEY_RANGE):
            # Multi-bit (1 byte) DPA Attack
            V[i][k] = SubBytes(p_i ^ k) if attackType == 2 else SubBytes((p_i ^ t_i) ^ k)


    return V


# Calculate Hamming Weight - number of symbols different from the zero-symbol
def hammingWeight(v):
    return bin(v).count("1")


def getHammingWeightMatrix(V):
    H = zeros((len(V), KEY_RANGE), uint8)
    for i in range(len(V)):
        for j in range(KEY_RANGE):
            H[i][j] = hammingWeight(V[i][j])
    return H


def getCorrcoef(inputs):
    global PC_a, PC_h, CC
    i, j = inputs
    PC_h = ctypeslib.as_array(PC_h)
    PC_a = ctypeslib.as_array(PC_a)
    CC = ctypeslib.as_array(CC)
    cor = corrcoef(PC_h[i], PC_a[j])[0][1]
    CC[i][j] = cor

def _init(PC_a1, PC_h1, CC1):
    """ Each pool process calls this initializer. Load the array to be populated into that process's global namespace """
    global PC_a, PC_h, CC
    PC_a = PC_a1
    PC_h = PC_h1
    CC = CC1

import ctypes
PC_h = []
PC_a = []
CC = []
def attackByte(byte_i, plaintexts, traces, attackType):
    global PC_a, PC_h, CC
    start = time.time()

    PC_h_base = multiprocessing.Array(ctypes.c_float, KEY_RANGE * SAMPLES)
    PC_h = ctypeslib.as_array(PC_h_base.get_obj())
    PC_h = PC_h.reshape(KEY_RANGE, SAMPLES)

    PC_a_base = multiprocessing.Array(ctypes.c_float, SAMPLES * TRACE_NUM)
    PC_a = ctypeslib.as_array(PC_a_base.get_obj())
    PC_a = PC_a.reshape(TRACE_NUM, SAMPLES)

    CC_base   = multiprocessing.Array(ctypes.c_float, KEY_RANGE * TRACE_NUM)
    CC = ctypeslib.as_array(CC_base.get_obj())
    CC = CC.reshape(KEY_RANGE, TRACE_NUM)






    # Get hypothetical intermediate values
    IV = getIntermediateValues(byte_i, plaintexts, attackType)
    # Power Consumption hypothetical
    PC_h = getHammingWeightMatrix(IV).transpose()
    # Power Consumption actual
    PC_a = matrix(traces).transpose()[:TRACE_NUM]

    inputs = []
    for i in range(0, KEY_RANGE):
        for j in range(0, TRACE_NUM):
            inputs.append((i, j))

    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=_init, initargs=(PC_a,PC_h, CC,))
    pool.map(getCorrcoef, inputs)


    end = time.time()
    print "Decryption time: %ds" % (end - start)
    return CC


key = []
for i in range(16):
       key.append(0)

key = [1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7]

texts = []
traces = []
attackType = []

def attack(i):
    global key, attackType, traces, texts

    print "\n Attacking %d Byte..." % i
    R = attackByte(i, texts, traces, attackType)
    max_coeff = R[0].max()
    keyByte = 0
    # Find the value in (0, 255) with the highest correlation coefficient.
    for k in range(1, KEY_RANGE):
        current_coeff = R[k].max()
        # If current coefficient value is larger (current k is more likely)
        if current_coeff > max_coeff:
            max_coeff = current_coeff
            keyByte = k
    key[i] = keyByte


def threading(texts, traces, attackType):
    print "Attacking key using the first %d data points from each trace for each sample" % TRACE_NUM



    # Make the Pool of workers
    # pool = ThreadPool(16)
    #
    # vals = []
    # for i in range(16):
    #     vals.append(i)
    #
    # results = pool.map(attack, vals)
    #
    # pool.close()
    # pool.join()


    key1 = ""

    for i in range(1):
        attack(i)
        newByte = ("%X" % key[i]).zfill(2)
        printComparison(newByte, i, attackType)
        key1 += newByte

    # list = [[] for i in range(4)]
    # for i in range(BYTES/4):
    #     for j in range(BYTES/4):
    #         list[i].append(key[(i+1) * j])
    #     print list[i]
    #
    # k_bytes = inv_key(reconstruct_key(list))
    # k = ByteListToHexString(k_bytes)


    return key1


if (__name__ == "__main__"):
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen(args=sys.argv[1],
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE)

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in = target.stdin

    # define multi-processing
    # num_of_workers = multiprocessing.cpu_count()
    # pool = multiprocessing.Pool(num_of_workers)

    # inputs = generateRandomInputs()
    # outputs, traces = generateSamples(inputs)

    inputs = CIPHERTEXTS
    # outputs, traces = generateSamples(inputs)
    # storeInfo(traces)
    traces = getInfo()
    outputs = []
    texts = inputs


    attackType = 2

    # # Execute a function representing the attacker.
    # # Attack key 2
    key2 = threading(inputs, traces, 2)


    key2 = "5B6BA73EB81D4840B21AE1DB10F61B8C"

    generateTweakValues(inputs, key2)

    attackType = 1

    # Attack key 1
    # key1 = threading(outputs, traces, 1)

    # print "\nGuess: key: " + key1 + key2
    print "True : Key: " + "1BEE5A32595F3F3EA365A590028B7017" + "5B6BA73EB81D4840B21AE1DB10F61B8C"







