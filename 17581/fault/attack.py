import random, sys, subprocess
from Utils import *

ORACLE_QUERIES = 0
BYTES = 16
KEY_RANGE = 256

# Expected label l and ciphertext c as octet strings
def interact( m, fault ) :
    # Send (fault, message) to attack target.
    target_in.write( "%s\n" % ( fault ) )
    target_in.write( "%s\n" % ( i2osp(m) ) )
    target_in.flush()
    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    c = target_out.readline().strip()
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return c

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



# def exh(hypotheses):
#     for (k1, k8, k11, k14) in hypotheses[0]:
#         for (k2, k5, k12, k15) in hypotheses[1]:
#             ii = 0
#             for (k3, k6, k9, k16) in hypotheses[2]:
#                 for (k4, k7, k10, k13) in hypotheses[3]:
#                     # key = step2_all(((0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16), x, xp))
#                     i += 1
#                     # if key != -1 :
#                     #     # print "Testing key: " + getString(key[1:])
#                     #     k = testKey(key)
#                     #     # k = testKey_2(key)
#                     #     if k != -1 :
#                     #         print "Key: " + k
#                     #         return 1
#                     inputs[ii] = (((0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16), x, xp))
#                     ii += 1
#



# Inject a fault and build hypotheses from this fault via step 1
def create_hypotheses(m, c):
    # m = Correct output, m_f = Fault output
    m = HexToByteList( m )
    # Inject fault at input to the eighth round - single fault attack
    m_f = HexToByteList( interact(c, "8,1,0,0,0") )

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
            delt_i = inv_s[ m[i] ^ k ] ^ inv_s[ m_f[i] ^ k ]
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
    return hypotheses

def attack(c, m):

    # Create first hypothesis
    hypotheses = create_hypotheses(m, c)

    # Repeat with another fault until we only have one hypothesis for each byte - This attack requires two faulty outputs.
    while max([len(hyps_i) for hyps_i in hypotheses]) > 1:
        # Add key_set if key_set is in byte_current and byte_previous. Repeat for each of the 4 bytes.
        next_hypotheses =[]
        current_hypotheses = create_hypotheses(m, c)

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
    # Generate random 128-bit ciphertext
    c = random.getrandbits(128)

    # Retrieve real m from oracle with no fault injection
    m = interact(c, "")

    # Attack using fault, retrieve k
    k = attack(c, m)

    # Check if key recovery is successful
    if AES_check(toHex(c),m, k):
        print "Key recovery Successful:"
        print " m = " + m
        print " c = " + toHex(c).strip() + "\n"
        print " Key recovered: " + k
        print " Oracle uses:   " + str(ORACLE_QUERIES)

    else:
        print "Error: Key NOT correct"
        print " Key recovered: " + k
        print "Trying again..."
        attackLoop()




if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    attackLoop()




# (1) - Differential Fault Analysis of the Advanced Encryption Standard using a Single Fault. Michael Tunstall1, Debdeep Mukhopadhyay2, and Subidh Ali.