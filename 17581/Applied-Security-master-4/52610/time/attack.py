import sys, subprocess
import random, math
from Crypto.Util import number
import numpy as np

# Public Key
N = 0
e = 0

# Private Key
d = 1

# Montgomery parameters
# word size
w = 64
# Base
b = (1 << w)
#
rho = 0
#
omega = 0
#
rho_sq = 0

# Ciphertext to be generated
size = 6000
# size = 20000

# Confidence level, when is the bit accepted?
level = 2.0

interactions = 0

# Test private key
def test (d) :
    m = 0x1234
    c = pow(m, e, N)
    m_r = pow(c, d, N)
    return m == m_r

def interact(ciphertext) :
    return interactD(ciphertext)
    # return interactR(ciphertext)

# interact with {user}.D
def interactD( ciphertext ) :
    global interactions
    interactions += 1

    # Send ciphertext to attack target.
    target_in.write( "%X\n" % ( ciphertext ) ) ; target_in.flush()

    # Receive ( time, message ) from attack target.
    # time = an execution time measured in clock cycles
    # m = plaintext, represented as a hexadecimal integer string
    time      = int( target_out.readline().strip() )
    message   = int( target_out.readline().strip(), 16 )

    return time

# interact with {user}.D
def interactR( ciphertext ) :
    global interactions
    interactions += 1

    d_test = 0x00865cf5bb77ebb9eaea94ee863cbc9d24705a12fdc0f2bb64788f0c117b8a4a02f62bd2930a708d3a405a4720b1e3093214b7da70db7285ba8c0dfca5113ee8d2d09c150a7e3c1eea2e48b145c9e6a4a55fd57940ef3eaa6b8031b861a62a18733aaadf5f7f6deb3032051bea7851056e8becbbab54e8cea46a188e05388fde79
    pk = 0xD8F45CD47C0CDDE7
    # Hamming weight
    hw = 36
    # time when sending 0
    t = 51712

    # Send ciphertext to attack target.
    target_in.write( "%X\n" % ( ciphertext ) ) ; target_in.flush()
    target_in.write( "%X\n" % ( N ) ) ; target_in.flush()
    target_in.write( "%X\n" % ( pk ) ) ; target_in.flush()

    # Receive ( time, message ) from attack target.
    # time = an execution time measured in clock cycles
    # m = plaintext, represented as a hexadecimal integer string
    time      = int( target_out.readline().strip() )
    message   = int( target_out.readline().strip(), 16 )

    return time

# Read Public Key from {user}.param
def readPK( name ) :
    file = open(name, 'r')
    global N, e
    N = int(file.readline(), 16)
    e = int(file.readline(), 16)
    file.close()

# Compute Montgomery rho
def getRho() :
    temp = 1
    while temp <= N :
        temp *= b
    return temp

# Compute Montgomery omega
def getOmega() :
    return (-number.inverse(N, rho)) % rho

# Compute Montgomery rho squared
def getRhoSq() :
    return pow(rho, 2, N)

# Get all Montgomery parameters
def montParam() :
    global rho, omega, rho_sq
    rho = getRho()
    omega = getOmega()
    rho_sq = getRhoSq()

# Montgomery Multiplication from: "Analyzing And Comparing Montgomery Multiplication
# Algorithms" (page 2)
def MonPro(a, b) :
    t = a * b
    u = (t + (t * omega % rho) * N) / rho
    Red = False
    # Check if reduction is needed
    if u >= N :
        u = u - N
        Red = True
    return (u, Red)

def generate(x) :
    global cipher
    cipher_append = cipher.append
    for i in range(x) :
        # ciphertext in [0,N)
        abc = random.getrandbits(1024)
        while abc >= N :
            abc = random.getrandbits(1024)
        cipher_append(abc)

# Square and multiply
# Square and multiplly for the first bit takes 1.5 steps (square, multiply, square)
# After performing square and multiply for the current bit we need an additional
# square operation to determine if there has been a reduction or not.
def SAM_init(ciphertext) :
    # Use Montgomery form
    temp, _ = MonPro(1, rho_sq)
    mform, _ = MonPro(ciphertext, rho_sq)

    # Square and multiply for current bit (first bit always set)
    temp, _ = MonPro(temp, temp)
    temp, _ = MonPro(temp, mform)

    # Square operation that determines if the reduction was performed
    temp, _ = MonPro(temp, temp)

    # Return temporary value of result, temp, and the value of the ciphertext
    # in Montgomery form c.
    return (temp, mform)

# Generate ciphertexts and apply square and multiply 1.5 steps
# and get the time
def initialize() :
    global cipher, cipher_temp, cipher_mform, cipher_time
    # Ciphertexts
    cipher = []
    # Ciphertexts in Montgomery form
    cipher_mform = []
    # Temporary value between ciphertext and plaintext
    cipher_temp = []
    # Time for each ciphertext
    cipher_time = []

    print "Generate ciphertexts."
    generate(size)

    cipher_time_append = cipher_time.append
    cipher_temp_append = cipher_temp.append
    cipher_mform_append = cipher_mform.append

    print "Working ..."
    for i in range(size) :
        time = interact(cipher[i])
        cipher_time_append(time)

        temp, mform = SAM_init(cipher[i])
        cipher_temp_append(temp)
        cipher_mform_append(mform)

def reinitialize() :
    global cipher, cipher_temp, cipher_mform, cipher_time, d
    # Ciphertexts
    cipher = []
    # Ciphertexts in Montgomery form
    cipher_mform = []
    # Temporary value between ciphertext and plaintext
    cipher_temp = []
    # Time for each ciphertext
    cipher_time = []

    print "Generate ciphertexts."
    generate(size)

    cipher_time_append = cipher_time.append
    cipher_temp_append = cipher_temp.append
    cipher_mform_append = cipher_mform.append

    # Remove last bit
    if d != 1 :
        d = d >> 1

    length = len(bin(d)) - 2

    print "Working ..."
    for i in range(size) :
        time = interact(cipher[i])
        cipher_time_append(time)
        temp, mform = SAM_init(cipher[i])
        cipher_mform_append(mform)
        for j in range(length-2, -1, -1) :
            temp, _ = SAM_bit(mform, temp, (d>>j)&1 )
        cipher_temp_append(temp)


# Square and multiply for all bits except the first (always 1) and last one.
# The function performs the multiply step for the current bit, and the squaring
# for the next bit to determine if there was a reduction.
def SAM_bit(mform, temp, bit) :
    if bit == 1 :
        temp, _ = MonPro(temp, mform)
    temp, Red = MonPro(temp, temp)
    return (temp, Red)

# Square and multiply improved
# At each step we need to compute square and multiply for both one and zero, we
# can remove the if statement
def SAM(mform, temp) :
    # When the bit is zero
    tempNotSet, redNotSet = MonPro(temp, temp)
    # When the bit is one
    tempSet, redSet = MonPro(temp, mform)
    tempSet, redSet = MonPro(tempSet, tempSet)

    return (tempNotSet, redNotSet, tempSet, redSet)

def getNext() :
    global cipher_temp, size, d, cipher_mform

    while True :
        # The bit is one, reduction
        BSetRed = [0, 0]
        # The bit is one, no reduction
        BSetNoRed = [0, 0]
        # The bit is zero, reduction
        BNotSetRed = [0, 0]
        # The bit is zero, no reduction
        BNotSetNoRed = [0, 0]

        ciphertext_temp = {}
        ciphertext_temp[0] = []
        ciphertext_temp[1] = []

        cipher_temp_notSet = ciphertext_temp[0].append
        cipher_temp_Set = ciphertext_temp[1].append

        for i in range(size) :
            tempNotSet, redNotSet, tempSet, redSet = SAM(cipher_mform[i], cipher_temp[i])

            cipher_temp_Set(tempSet)
            if redSet :
                BSetRed[0] += cipher_time[i]
                BSetRed[1] += 1
            else :
                BSetNoRed[0] += cipher_time[i]
                BSetNoRed[1] += 1

            cipher_temp_notSet(tempNotSet)
            if redNotSet :
                BNotSetRed[0] += cipher_time[i]
                BNotSetRed[1] += 1
            else :
                BNotSetNoRed[0] += cipher_time[i]
                BNotSetNoRed[1] += 1

        M1 = BSetRed[0]/float(BSetRed[1])
        M2 = BSetNoRed[0]/float(BSetNoRed[1])
        M3 = BNotSetRed[0]/float(BNotSetRed[1])
        M4 = BNotSetNoRed[0]/float(BNotSetNoRed[1])

        diff_0 = abs(M3-M4)
        diff_1 = abs(M1-M2)
        diff = abs(diff_0 - diff_1)

        if ( diff_1 > diff_0) and diff > level :
            cipher_temp = ciphertext_temp[1]
            return 1, diff
        elif ( diff_1 < diff_0) and diff > level :
            cipher_temp = ciphertext_temp[0]
            return 0, diff
        else :
            print "Confidence level: " + str(diff)
            print "Can't tell."
            # Generate ciphertexts
            reinitialize()

def attack() :
    global cipher, cipher_mform, cipher_temp, cipher_time, d

    if test(d) :
        print "Found key: " + str(bin(d))
        return

    # Last bit can't be guessed, try the two possible values
    # d0 = (d << 1)
    # In Python it is faster to add than to shift or multiply
    d0 = d + d
    if test(d0) :
        print "Found key: " + str(bin(d0))
        d = d0
        return
    # d1 = (d << 1) | 1
    d1 = d + d + 1
    if test(d1) :
        print "Found key: " + str(bin(d1))
        d = d1
        return

    initialize()

    print "Start guessing ..."
    print str(bin(d))[2:]

    # Loop until the key is found
    while True :
        bit, cl = getNext()
        # d = (d << 1) | bit
        d = d + d + bit

        # print "Confidence level: " + str(cl)
        print str(bin(d))[2:]

        # Last bit can't be guessed, try the two possible values
        # d0 = (d << 1)
        d0 = d + d
        if test(d0) :
            print "Last bit guessed: 0"
            print "Found key: " + str(bin(d0))
            d = d0
            break
        # d1 = (d << 1) | 1
        d1 = d + d + 1
        if test(d1) :
            print "Last bit guessed: 1"
            print "Found key: " + str(bin(d1))
            d = d1
            break

        if d >= N :
            print "\nSomething went wrong."
            # Generate ciphertexts
            initialize()
            # Reset private key
            d = 1
            sys.stdout.write('1'); sys.stdout.flush();

if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read public parameters
    readPK(sys.argv[2])
    # Compute Montgomery parameters: rho, omega and rho squared
    montParam()
    #
    attack()
    #
    print "Key in hex: " +str("%X" %d)
    #
    print "Number of interactions with the attack target: " + str(interactions)
