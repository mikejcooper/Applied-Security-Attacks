import multiprocessing
import subprocess
import sys
import random
import warnings

from numpy import ctypeslib

import time
from numpy import matrix, corrcoef, float32, uint8
from numpy.ma import zeros
import Queue
import threading
import urllib2
from multiprocessing.dummy import Pool as ThreadPool
import ctypes


from Utils import *



OCTET_SIZE      = 32
BYTES           = 16
SAMPLES         = 20
CIPHERTEXTSIZE  = 128
KEY_RANGE       = 256
TRACE_NUM       = 3000
CHUNKSIZE       = 4
MINCONFIDENCE   = 1
TWEAKS          = []


# Shared memory arrays
PC_h = []
PC_a = []
CC = []

def SubBytes(x):
    return s[x]

def _init(PC_a1, PC_h1, CC1):
    """ Each pool process calls this initializer. Load the array to be populated into that process's global namespace """
    global PC_a, PC_h, CC
    PC_a = PC_a1
    PC_h = PC_h1
    CC = CC1

def _initSharedMemory():
    global PC_a, PC_h, CC
    warnings.filterwarnings("ignore")

    PC_h_base = multiprocessing.Array(ctypes.c_float, KEY_RANGE * SAMPLES)
    PC_h = ctypeslib.as_array(PC_h_base.get_obj())
    PC_h = PC_h.reshape(KEY_RANGE, SAMPLES)

    PC_a_base = multiprocessing.Array(ctypes.c_float, SAMPLES * TRACE_NUM)
    PC_a = ctypeslib.as_array(PC_a_base.get_obj())
    PC_a = PC_a.reshape(TRACE_NUM, SAMPLES)

    CC_base = multiprocessing.Array(ctypes.c_float, KEY_RANGE * TRACE_NUM)
    CC = ctypeslib.as_array(CC_base.get_obj())
    CC = CC.reshape(KEY_RANGE, TRACE_NUM)

def generateRandomInputs() :
    samples = []
    for i in range(0, SAMPLES):
        sample = "%X" % random.getrandbits(CIPHERTEXTSIZE)
        samples.append(sample.zfill(32))
    return samples

def generateSamples(inputs):
    print "Generating %d samples..." % SAMPLES
    traces = []; outputs = [];
    for i in inputs:
        _traces, _output = interact(i)
        traces.append(_traces)
        outputs.append(_output)
    return (outputs, traces)

def generateTweakValues(inputs, key2):
    global TWEAKS
    for i in inputs:
        T = AES.new(HexToByte(key2)).encrypt(HexToByte(i))
        T = ByteToHex(T)
        # Next operation: Group multiplication with j, but j = 0. Therefore T stays the same.
        TWEAKS.append(T)

def interact(input):
    j = "000"

    target_in.write("%s\n" % j)
    target_in.write("%s\n" % input)
    target_in.flush()

    # Receive power consumption trace and ciphertext from attack target.
    trace = target_out.readline().strip()
    plaintext = target_out.readline().strip().zfill(32)

    traces = getTrace(trace)
    return (traces, plaintext)

# Get hypothetical intermediate values
def getIntermediateValues(byte_i, plaintexts, attackType):
    V = zeros((len(plaintexts), KEY_RANGE), uint8)
    # For current byte, enumerate over each ciphertext and compute each possible key value
    for i, p in enumerate(plaintexts):
        p_i = getByte(p, byte_i)
        t_i = 0 if attackType == 2 else getByte(TWEAKS[i], byte_i)

        for k in range(KEY_RANGE):
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
    (i, j1, j2) = inputs
    PC_h = ctypeslib.as_array(PC_h)
    PC_a = ctypeslib.as_array(PC_a)
    CC = ctypeslib.as_array(CC)
    cor = corrcoef(PC_h[i], PC_a[j1:j2])[0][1]
    CC[i][j1:j2] = cor

def attackByte(byte_i, plaintexts, traces, attackType):
    global PC_a, PC_h, CC
    start = time.time()

    # Get hypothetical intermediate values
    IV = getIntermediateValues(byte_i, plaintexts, attackType)
    # Power Consumption hypothetical
    PC_h = getHammingWeightMatrix(IV).transpose()
    # Power Consumption actual
    PC_a = matrix(traces).transpose()[:TRACE_NUM] if attackType == 2 else matrix(traces).transpose()[len(traces[0]) - TRACE_NUM : len(traces[0])]

    chunks = TRACE_NUM / CHUNKSIZE
    inputs = []
    for i in range(0, KEY_RANGE):
        for j in range(chunks):
            j1 = j * CHUNKSIZE
            j2 = (j + 1) * CHUNKSIZE
            inputs.append( (i, j1, j2) )

    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=_init, initargs=(PC_a,PC_h, CC,))
    pool.map(getCorrcoef, inputs)
    pool.close()
    pool.join()

    end = time.time()
    print "Decryption time: %ds" % (end - start)
    return CC

def AttackBytes(texts, traces, attackType):
    global key, MINCONFIDENCE
    key1 = ""
    keyByte = 0

    for i in range(16):

        print "\nAttacking %d Byte..." % i

        R = attackByte(i, texts, traces, attackType)
        max_coeff = R[0].max()

        # Find the value in (0, 255) with the highest correlation coefficient.
        for k in range(1, KEY_RANGE):
            current_coeff = R[k].max()
            # If current coefficient value is larger (current k is more likely)
            if current_coeff > max_coeff:
                max_coeff = current_coeff
                keyByte = k

        print "Confidence: %f" % max_coeff

        if (MINCONFIDENCE > max_coeff) :
            MINCONFIDENCE = max_coeff

        newByte = toHex(keyByte)
        printComparison(newByte, i, attackType)
        key1 += newByte

    return key1


def Attack():

    _initSharedMemory()

    inputs = generateRandomInputs()
    outputs, traces = generateSamples(inputs)
    traces = sameLengthTraceSets(traces)

    # Attack key 2
    print "\nAttacking Key 2:"
    key2 = AttackBytes(inputs, traces, 2)

    # key2 = "2BDC1E95C035F9520ACF58EEC0C30B88"
    print "\nKey 2: " + key2

    generateTweakValues(inputs, key2)

    # Attack key 1
    print "\nAttacking Key 1:"
    key1 = AttackBytes(outputs, traces, 1)

    print "\nKey 1: " + key1

    return (key1, key2)


if (__name__ == "__main__"):
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen(args=sys.argv[1],
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE)

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in = target.stdin

    key1, key2 = Attack()


    print "Minimum confidence value: %f" % MINCONFIDENCE

    if (MINCONFIDENCE < 0.91):
        print "\nGuess: key: " + key1 + key2
        print "Warning: Minimum confidence value below threshold, RETRYING... "
        print "Increasing Sample Size"
        SAMPLES *= 2
        Attack()

    print "\nGuess: key: " + key1 + key2
    print "True : Key: " + "4BD55725A2D190A44D73764FE3EC68F7" + "2BDC1E95C035F9520ACF58EEC0C30B88"
    print "Oracle uses:", str(SAMPLES)
    print "Number of traces per attack:", str(TRACE_NUM)


#   K1: 4BD55725A2D190A44D73764FE3EC68F7
#   K2: 2BDC1E95C035F9520ACF58EEC0C30B88







