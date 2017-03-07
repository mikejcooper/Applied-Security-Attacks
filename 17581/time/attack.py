import sys, subprocess
import math
import random
from montgomery import *


ORACLE_QUERIES = 0


# Defining the word length todo set as runtime ??
w = 64
b = 1 << w
mask = pow(2,w) - 1


def Read_Params( file ) :
    # Read RSA modulus N
    N = file.readline().strip()
    # RSA public exponent e
    e = file.readline().strip()
    return ( N, e )

def Initialise_Input( N, e ) :
    N = int(N, 16) # Convert Hex to Int
    e = int(e, 16) # Convert Hex to Int
    return ( N, e )

def Interact( c ) :
    # Send Ciphertext c as Hexidecimal string to attack target.
    target_in.write( "%s\n" % ( toHex(c) ) )
    target_in.flush()
    # Receive ( Time t, Message m ) from attack target.
    t = int(target_out.readline().strip())
    m = int(target_out.readline().strip(), 16)
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return ( t, m )

def playground() :
    m1 = toHexInt("hello My name is michael james cooper and I hope this is a large numberr")
    c = pow_mod(m1, e, N)

    (t, m) = Interact(c)


    print "time: " + str(t)
    print "message: " + Int2Hex2Char(m)


# Generate test ciphertexts
def generate_cs(N, d, r_sq, omega):
    c_time = []
    c_p = []
    c_cur = []

    print "Generating messages"
    for i in range(13000):
        c = random.randint(0, N)            # Produce random Ciphertext between 0 <= c <= N
        time, test_message = Interact(c)    # Interact using random Ciphertext
        c_time.append(time)                 # Store time

        c_mont, _ = mont_mul(c, r_sq, N, omega) # Calculate:  c * r_sq mod N
        c_p.append(c_mont)                       # Store

        c_cur.append(mont_L2R_exp(c_mont, d, N, r_sq, omega)) # Calculate and Store

    return c_time, c_p, c_cur, c, test_message





def Attack ( N , e ) :
    # Initialise Montgomery Params
    omega, r_sq = mont_omega(N), mont_r_sq(N)

    d = 1



    c_time, c_p, c_cur, test_c, test_message = generate_cs(N, d, r_sq, omega)


    d = 1
    n = 1
    print "Testing key bits"
    for n in range( 0, w) :  # For each bit in private exponent d
        c_0 = []
        c_1 = []
        # Fill in the reduction sets
        bit0_red = []
        bit0_nored = []
        bit1_red = []
        bit1_nored = []
        for i, c in enumerate(c_p):
            ci_0, _ = mont_mul(c_cur[i], c_cur[i], N, omega)
            c_0.append(ci_0)
            ci_0, red0 = mont_mul(ci_0, ci_0, N, omega)
            if red0:
                bit0_red.append(c_time[i])
            else:
                bit0_nored.append(c_time[i])
            ci_1, _ = mont_mul(c_cur[i], c_cur[i], N, omega)
            ci_1, _ = mont_mul(ci_1, c, N, omega)
            c_1.append(ci_1)
            ci_1, red1 = mont_mul(ci_1, ci_1, N, omega)
            if red1:
                bit1_red.append(c_time[i])
            else:
                bit1_nored.append(c_time[i])

        # Calculate the distinguisher
        mean_bit0_red = sum(bit0_red) // len(bit0_red)
        mean_bit0_nored = sum(bit0_nored) // len(bit0_nored)
        mean_bit1_red = sum(bit1_red) // len(bit1_red)
        mean_bit1_nored = sum(bit1_nored) // len(bit1_nored)
        diff_0 = mean_bit0_red - mean_bit0_nored
        diff_1 = mean_bit1_red - mean_bit1_nored

        # Statistically guess a bit
        # If there is no difference, regenerate all messages and try this bit again
        if diff_0 > diff_1:
            d <<= 1
            c_cur = c_0
        elif diff_1 > diff_0:
            d = (d << 1) + 1
            c_cur = c_1
        else:
            print "Can't distinguish a bit"
            print "Bit 0: %d" % diff_0
            print "Bit 1: %d" % diff_1
            print "Regenerating Messages"
            c_time, c_p, c_cur, num_interactions, test_c, test_message = generate_cs(N, d, r_sq, omega)

        print "Guessing bit %d, Key: %X" % (n, d)
        # Test if we have recovered the key by decrypting a ciphertext
        # This is done by bruteforcing the final bit, as we can't exploit
        # the square in the next round due to there not being another round
        if pow(test_c, d << 1, N) == test_message:
            d <<= 1
            break
        elif pow(test_c, (d << 1) + 1, N) == test_message:
            d = (d << 1) + 1
            break

    # Print results
    print "Key Recovered"
    print "Key: %X" % d
    print "Message decrypted by key: %X" % pow(test_c, d, N)
    print "Message decrypted by system: %X" % test_message


    return "Hi"


def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

# Convert to Hex string
def toHex(X):
    if isinstance(X, ( int, long )):
        return "%X\n" % X
    elif X == '':
        return 0
    else:
        return X.encode('hex')

# Convert to integer value of Hex string
def toHexInt(X):
    if isinstance(X, ( int, long )):
        return int(hex(X), 16)
    elif X == '':
        return 0
    else:
        return int(X.encode('hex'), 16)

# Convert to Hex string
def fromHex(X):
    if X == '':
        return 0
    else:
        return X.strip().decode('hex')

# Convert to Hex string
def Int2Hex2Char(X):
    if X == '':
        return 0
    else:
        return toHex(X).strip().decode('hex')

# Convert from Hex string to integer
def Hex2Int(X):
    if X == '':
        return 0
    else:
        return int(X, 16)




if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read from file
    (N, e) = Read_Params(open(sys.argv[2], 'r'))

    # ( Modulus, Public exponent )
    (N, e) = Initialise_Input(N, e)



    # RSA OAEP Decryption
    Message = Attack(N, e)

    # print "Decoded Message: " + Message
    print "Oracle uses:", str(ORACLE_QUERIES)














