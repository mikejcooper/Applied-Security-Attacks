import multiprocessing
import random, sys, subprocess
import ctypes
import numpy
import warnings
from numpy import ctypeslib

import time

from Utils import *

ORACLE_QUERIES = 0
BYTES = 16
KEY_RANGE = 256
BLOCK_SIZE = 128

MULTAB = numpy.zeros((7, KEY_RANGE), dtype=int)
m_org = ""
c_org = ""

# Shared memory arrays
Hypothesis = []
M = []
M_fault = []


def _initaliseMultTable():
    # 2x
    for i in range(KEY_RANGE):
        MULTAB[0][i] = mul(2, i)
    # 3x
    for i in range(KEY_RANGE):
        MULTAB[1][i] = mul(3, i)
    # 6x
    for i in range(KEY_RANGE):
        MULTAB[2][i] = mul(6, i)
    # 9x
    for i in range(KEY_RANGE):
        MULTAB[3][i] = mul(9, i)
    # 11x
    for i in range(KEY_RANGE):
        MULTAB[4][i] = mul(11, i)
    # 13x
    for i in range(KEY_RANGE):
        MULTAB[5][i] = mul(13, i)
    # 14x
    for i in range(KEY_RANGE):
        MULTAB[6][i] = mul(14, i)

def _init(PC_a1, PC_h1, CC1):
    """ Each pool process calls this initializer. Load the array to be populated into that process's global namespace """
    global PC_a, PC_h, CC
    PC_a = PC_a1
    PC_h = PC_h1
    CC = CC1

def _initSharedMemory(hypothesis, m, m_fault):
    global Hypothesis, M, M_fault
    warnings.filterwarnings("ignore")

    maxSubHyp = 0
    for sub in hypothesis:
        if len(sub) > maxSubHyp:
            maxSubHyp = len(sub)

    Hypothesis_base = multiprocessing.Array(ctypes.c_int, len(hypothesis) * maxSubHyp)
    Hypothesis = ctypeslib.as_array(Hypothesis_base.get_obj())
    Hypothesis = Hypothesis.reshape(maxSubHyp, len(hypothesis))
    Hypothesis = hypothesis

    M_base = multiprocessing.Array(ctypes.c_int, len(m))
    M = ctypeslib.as_array(M_base.get_obj())
    M = M.reshape(len(m), 1)
    M = m

    M_fault_base = multiprocessing.Array(ctypes.c_int, len(m_fault))
    M_fault = ctypeslib.as_array(M_fault_base.get_obj())
    M_fault = M_fault.reshape(len(m_fault), 1)
    M_fault = m_fault


# Expected label l and ciphertext c as octet strings
def interact(m, fault):
    # Send (fault, message) to attack target.
    target_in.write("%s\n" % (fault))
    target_in.write("%s\n" % (i2osp(m)))
    target_in.flush()
    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    c = target_out.readline().strip()
    globals().update(ORACLE_QUERIES=ORACLE_QUERIES + 1)
    return c


# Inverses the whole key from the tenth round
def inv_key(k):
    for i in range(10, 0, -1):
        k[4:] = \
            [
                k[0] ^ k[4], k[1] ^ k[5], k[2] ^ k[6], k[3] ^ k[7],
                k[4] ^ k[8], k[5] ^ k[9], k[6] ^ k[10], k[7] ^ k[11],
                k[8] ^ k[12], k[9] ^ k[13], k[10] ^ k[14], k[11] ^ k[15]
            ]

        k[1:4] = [s[k[14]] ^ k[1], s[k[15]] ^ k[2], s[k[12]] ^ k[3]]

        k[0] = s[k[13]] ^ k[0] ^ r_con[i]
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


def maths(params):
    global Hypothesis, M, M_fault
    (i1, i2, i3, i4) = params

    k1, k14, k11, k8 = Hypothesis[0][i1]
    k5, k2, k15, k12 = Hypothesis[1][i2]
    k9, k6, k3, k16 = Hypothesis[2][i3]
    k13, k10, k7, k4 = Hypothesis[3][i4]

    k = (0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16)
    x = M
    xp = M_fault

    # 2*f
    a = inv_s[MULTAB[6][inv_s[x[1] ^ k[1]] ^ k[1] ^ s[k[14] ^ k[10]] ^ r_con[10]] ^
              MULTAB[4][inv_s[x[14] ^ k[14]] ^ k[2] ^ s[k[15] ^ k[11]]] ^
              MULTAB[5][inv_s[x[11] ^ k[11]] ^ k[3] ^ s[k[16] ^ k[12]]] ^
              MULTAB[3][inv_s[x[8] ^ k[8]] ^ k[4] ^ s[k[13] ^ k[9]]]] ^ inv_s[
              MULTAB[6][inv_s[xp[1] ^ k[1]] ^ k[1] ^ s[k[14] ^ k[10]] ^ r_con[10]] ^
              MULTAB[4][inv_s[xp[14] ^ k[14]] ^ k[2] ^ s[k[15] ^ k[11]]] ^
              MULTAB[5][inv_s[xp[11] ^ k[11]] ^ k[3] ^ s[k[16] ^ k[12]]] ^
              MULTAB[3][inv_s[xp[8] ^ k[8]] ^ k[4] ^ s[k[13] ^ k[9]]]]

    # f
    b = inv_s[MULTAB[3][inv_s[x[13] ^ k[13]] ^ k[13] ^ k[9]] ^
              MULTAB[6][inv_s[x[10] ^ k[10]] ^ k[10] ^ k[14]] ^
              MULTAB[4][inv_s[x[7] ^ k[7]] ^ k[15] ^ k[11]] ^
              MULTAB[5][inv_s[x[4] ^ k[4]] ^ k[16] ^ k[12]]] ^ inv_s[
              MULTAB[3][inv_s[xp[13] ^ k[13]] ^ k[13] ^ k[9]] ^
              MULTAB[6][inv_s[xp[10] ^ k[10]] ^ k[10] ^ k[14]] ^
              MULTAB[4][inv_s[xp[7] ^ k[7]] ^ k[15] ^ k[11]] ^
              MULTAB[5][inv_s[xp[4] ^ k[4]] ^ k[16] ^ k[12]]]

    # check 2*f == f
    if a != MULTAB[0][b]:
        return -1

    # f
    c = inv_s[MULTAB[5][inv_s[x[9] ^ k[9]] ^ k[9] ^ k[5]] ^
              MULTAB[3][inv_s[x[6] ^ k[6]] ^ k[10] ^ k[6]] ^
              MULTAB[6][inv_s[x[3] ^ k[3]] ^ k[11] ^ k[7]] ^
              MULTAB[4][inv_s[x[16] ^ k[16]] ^ k[12] ^ k[8]]] ^ inv_s[
              MULTAB[5][inv_s[xp[9] ^ k[9]] ^ k[9] ^ k[5]] ^
              MULTAB[3][inv_s[xp[6] ^ k[6]] ^ k[10] ^ k[6]] ^
              MULTAB[6][inv_s[xp[3] ^ k[3]] ^ k[11] ^ k[7]] ^
              MULTAB[4][inv_s[xp[16] ^ k[16]] ^ k[12] ^ k[8]]]

    # check f == f
    if b != c:
        return -1

    # 3*f
    d = inv_s[MULTAB[4][inv_s[x[5] ^ k[5]] ^ k[5] ^ k[1]] ^
              MULTAB[5][inv_s[x[2] ^ k[2]] ^ k[6] ^ k[2]] ^
              MULTAB[3][inv_s[x[15] ^ k[15]] ^ k[7] ^ k[3]] ^
              MULTAB[6][inv_s[x[12] ^ k[12]] ^ k[8] ^ k[4]]] ^ inv_s[
              MULTAB[4][inv_s[xp[5] ^ k[5]] ^ k[5] ^ k[1]] ^
              MULTAB[5][inv_s[xp[2] ^ k[2]] ^ k[6] ^ k[2]] ^
              MULTAB[3][inv_s[xp[15] ^ k[15]] ^ k[7] ^ k[3]] ^
              MULTAB[6][inv_s[xp[12] ^ k[12]] ^ k[8] ^ k[4]]]

    # check f == 3*f
    if MULTAB[1][c] != d:
        return -1

    # check 2*f == f == f == 3*f
    if MULTAB[1][a] == MULTAB[2][b] == MULTAB[2][c] == MULTAB[0][d]:
        return [k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16]
    else:
        return -1


def attackSingleFault(m, m_fault, hypotheses):
    global Hypothesis, M, M_fault, m_org, c_org

    m = getByteList(m)
    m_fault = getByteList(m_fault)

    _initaliseMultTable()
    _initSharedMemory(hypotheses, m, m_fault)

    # Create pools for multiprocessing and link to shared data structures
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=_init,
                                initargs=(Hypothesis, M, M_fault,))

    inputs = [None] * len(hypotheses[2]) * len(hypotheses[3])
    length = str(len(hypotheses[0]))

    for i1 in range(len(hypotheses[0])):
        start1 = time.time()
        for i2 in range(len(hypotheses[1])):
            i = 0
            for i3 in range(len(hypotheses[2])):
                for i4 in range(len(hypotheses[3])):
                    inputs[i] = ((i1, i2, i3, i4))
                    i += 1

            for key in pool.map(maths, inputs):
                if key != -1:
                    key = HexListToString(inv_key(key))
                    print "  Found potential key: " + key
                    # Check if key recovery is successful
                    if AES_check(toHex(c_org), m_org, key):
                        print " Exhaustive Key Recovery Successful:"
                        return key
        print "Round : " + str(i1 + 1) + " / " + length
        end1 = time.time()
        print "    Time:        %f" % (end1 - start1)


# Inject a fault and build hypotheses from this fault via step 1
def create_hypotheses(m, c):
    # m = Correct output, m_f = Fault output
    m = HexToByteList(m)
    # Inject fault at input to the eighth round - single fault attack
    m_f = HexToByteList(interact(c, "8,1,0,0,0"))

    # Create 256 (hypothesis values) by 16 (bytes) list
    HV = [[[] for i in range(KEY_RANGE)] for i in range(BYTES)]

    # Perform the exhaustive search on the each of the equations
    # For each byte, ki, in key k - consider the state of the differences after the ninth round shift row
    for i in range(BYTES):
        if i in [0, 2, 9, 11]:
            d_mult = delta2
        elif i in [7, 5, 14, 12]:
            d_mult = delta3
        elif i in [1, 3, 4, 6, 8, 10, 13, 15]:
            d_mult = delta1
        # For each potential value of key ki in range [0...255]
        for k in range(256):
            # 1/2/3 * delta = S^-1 ( m_i ^ k ) ^ S^-1 ( m_f_i ^ k )      -   Equation from paper (1)
            delt_i = inv_s[m[i] ^ k] ^ inv_s[m_f[i] ^ k]
            for j, delt in enumerate(d_mult):
                # Check: 1/2/3 * delta ==  delt == delt_i
                # If d_i matches index of delta matrix, then result is valid - we have found a hypothesis for the ith byte. Append to list of hypothesises.
                if delt_i == delt:
                    HV[i][j].append(k)

    hypotheses = [[] for i in range(4)]

    # Only add the hypotheses for each delta if there is a valid hypothesis for ki in all of the four equations for a given delta
    for cnt, bytes in enumerate([[0, 13, 10, 7], [4, 1, 14, 11], [8, 5, 2, 15], [12, 9, 6, 3]]):
        for i in range(KEY_RANGE):
            # If a valid solution (key) exists for each of the 4 equations.
            if HV[bytes[0]][i] and HV[bytes[1]][i] and HV[bytes[2]][i] and HV[bytes[3]][i]:
                # Obtain unique solution (filter duplicates) for each equation.
                hypotheses[cnt] += [[key0, key1, key2, key3]
                                    for key0 in HV[bytes[0]][i]
                                    for key1 in HV[bytes[1]][i]
                                    for key2 in HV[bytes[2]][i]
                                    for key3 in HV[bytes[3]][i]]
    return hypotheses, m_f, m


def attackMultiFault(hypotheses):
    # Repeat with another fault until we only have one hypothesis for each byte - This attack requires two faulty outputs.
    while max([len(hyps_i) for hyps_i in hypotheses]) > 1:
        # Add key_set if key_set is in byte_current and byte_previous. Repeat for each of the 4 bytes.
        next_hypotheses = []
        current_hypotheses = create_hypotheses(m_org, c_org)[0]

        for byte_current in current_hypotheses:
            matching_keys = []
            for byte_previous in hypotheses:
                for keys_current in byte_current:
                    for keys_previous in byte_previous:
                        if keys_current == keys_previous:
                            matching_keys.append(keys_current)
            next_hypotheses.append(matching_keys)
        hypotheses = next_hypotheses

    # Extract first list from byte - Termination of while loop means there will only be 1 list in each byte hypothesis.
    hypotheses = [bytes[0] for bytes in hypotheses]

    k_bytes = inv_key(reconstruct_key(hypotheses))

    k = ByteListToHexString(k_bytes)

    return k


def attackLoop():
    global m_org, c_org

    # Generate random 128-bit ciphertext
    c_org = random.getrandbits(128)

    # Retrieve real m from oracle with no fault injection
    m_org = interact(c_org, "")

    # Form first hypothesis
    hypotheses, m_f_list, m_list = create_hypotheses(m_org, c_org)

    print "Multi-Fault Attack...\n"

    # Attack using fault, retrieve k
    k = attackMultiFault(hypotheses)

    # Check if key recovery is successful
    if AES_check(toHex(c_org), m_org, k):
        print "Key recovery Successful:"
        print " m = " + m_org
        print " c = " + toHex(c_org).strip() + "\n"
        print " Key recovered: " + k
        print " Oracle uses:   " + str(ORACLE_QUERIES)

    else:
        print "Error: Key NOT correct"
        print " Key recovered: " + k
        print "Trying again..."
        attackLoop()

    print "\nSingle Fault attack..."
    print "WARNING: Starting exhaustive search, wall time is long..."
    # Attack using fault, retrieve k
    k = attackSingleFault(m_list, m_f_list, hypotheses)
    # Check if key recovery is successful
    if AES_check(toHex(c_org), m_org, k):
        print "Key recovery Successful:"
        print " m = " + m_org
        print " c = " + toHex(c_org).strip() + "\n"
        print " Key recovered: " + k
        print " Oracle uses:   " + str(ORACLE_QUERIES)

    else:
        print "Error: Key NOT correct"
        print " Key recovered: " + k
        print "Trying again..."
        attackLoop()


if (__name__ == "__main__"):
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen(args=sys.argv[1],
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE)

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in = target.stdin

    attackLoop()



    # (1) - Differential Fault Analysis of the Advanced Encryption Standard using a Single Fault. Michael Tunstall1, Debdeep Mukhopadhyay2, and Subidh Ali.