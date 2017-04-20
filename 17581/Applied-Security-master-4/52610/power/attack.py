import sys, subprocess, random
from numpy import zeros
from numpy import matrix
from numpy import uint8
from numpy import float32
from numpy import corrcoef
from struct import pack
from struct import unpack
try:
    from Crypto.Cipher import AES
    crypto_available = True
except ImportError :
    crypto_available = False


OCTET_SIZE = 32
BYTES = 16
SAMPLES = 150
BITSIZE = 128
KEYS = 256
TRACES = 1500

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

def SubBytes(x) :
    return sbox[x]

def interactD( plaintext ) :
  # Send plaintext to attack target.
  target_in.write( ("%s\n" % ( plaintext )).zfill(OCTET_SIZE) ) ; target_in.flush()

  # Receive power consumption trace and ciphertext from attack target.
  trace      = target_out.readline().strip()
  ciphertext = int(target_out.readline().strip(), 16)

  traces = getPowerTrace(trace)

  return (traces, ciphertext)

def getPowerTrace(trace) :
    traces_l = trace.split(',')

    length = int(traces_l[0])

    traces = []
    tadd = traces.append

    for i in range(1, TRACES+1) :
        tadd(int(traces_l[i]))

    return traces

# return new sample with trace and its ciphertext
def getNew() :
    # generate random plaintext
    plaintext = "%X" % random.getrandbits(BITSIZE)
    traces, ciphertext = interactD(plaintext)
    # return fixed number of traces
    return plaintext, traces

def getByte(number, index) :
    ByteString = (number).zfill(OCTET_SIZE)
    byte = ByteString[index*2 : (index+1)*2]
    return int(byte, 16)

# Get hypothetical intermediate values
def getV(byte, plaintexts) :
    V = zeros((SAMPLES, KEYS), uint8)

    for i, p in enumerate(plaintexts) :
        p_i = getByte(p, byte)
        for k in range(KEYS) :
            V[i][k] = SubBytes(p_i ^ k)

    return V

# Calculate Hamming Weight
def hammingWeight(v) :
    return bin(v).count("1")

def getHammingWeightMatrix(V) :
    HW = zeros((SAMPLES, KEYS), uint8)

    for i in range(SAMPLES) :
        for j in range(KEYS) :
            HW[i][j] = hammingWeight(V[i][j])

    return HW

def attackByte(byte, samples) :
    (plaintexts, traces) = samples
    V = getV(byte, plaintexts)
    # Calculate hypothetical power consumption
    H = getHammingWeightMatrix(V)

    R = zeros((KEYS, TRACES), float32)

    # Transpose H and T, each column becomes a row. Easier to access rows.
    H_t = H.transpose()
    T_t = traces.transpose()

    # Compute the correlation between each column of H and each column of T.
    for i in range(KEYS) :
        for j in range(TRACES) :
            # Correlation matrix is symmetric, [0][1] = [1][0]
            R[i][j] = corrcoef(H_t[i], T_t[j])[0][1]

    return R

def attack() :
    #Generate samples
    print "Generating %d samples ..." % SAMPLES
    print "Power trace: %d data points." % TRACES
    plaintexts = []
    traces = []
    for i in range(SAMPLES):
        (p, t) = getNew()
        plaintexts.append(p)
        traces.append(t)

    # Measured power traces
    T = matrix(traces)

    samples = (plaintexts, T)

    key = ""

    print "Start guessing key ..."
    for i in range(BYTES):
        R = attackByte(i, samples)
        max_tr = R[0].max()
        keyByte = 0
        # Find the value in (0, 255) that has the highest correlation coefficient.
        for k in range(1,KEYS):
            temp = R[k].max()
            if temp > max_tr :
                max_tr = temp
                keyByte = k
        newByte = ("%X" % keyByte).zfill(2)
        key += newByte
        sys.stdout.write("Byte {0:<7}: {1:<51}\n".format(i, newByte))

    # Check if the recovered key is valid.
    if crypto_available :
        result = testKey(key)
    else :
        result = testKey_2(key)
    if result == 1:
        print "Key :"+key
        print int(key, 16)
        return 1
    return 0

# Test if recovered key is valid
def getHexList(x) :
    l = []
    for i in range(BYTES) :
        byte_i = getByte(x, i)
        l.append(byte_i)
    return l

def getHexString(x) :
    string = ""
    for i in x:
        string += ("%X" % i).zfill(2)
    return string

def testKey(key):
    key = getHexList(key)
    key = pack(16*"B", *key)

    enc = AES.new(key)

    p = "%X" % random.getrandbits(BITSIZE)
    plain = getHexList(p)
    plain = pack(16*"B", *plain)

    _, cipher_1 = interactD(p)

    c = enc.encrypt(plain)
    c = unpack(16*"B", c)
    c = getHexString(c)
    cipher_2 = int(c, 16)

    if cipher_1 == cipher_2:
        return 1
    return 0

def testKey_2(key):
    recovered_key = "61A4C140DD7409B8066A36F92AEF097A"
    if key == recovered_key :
        return 1
    return 0

if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Execute a function representing the attacker.
    while True:
        if attack() == 1:
            break
        else :
            print "Restart attack ..."
            SAMPLES += 50
            TRACES += 500
