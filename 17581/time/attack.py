import sys, subprocess
import math
import random
from timeit import default_timer

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
    times , c_p, c_cur = [], [], []
    print "Generating messages"
    for i in range(13000):
        c = random.randint(0, N)                        # Produce random Ciphertext between 0 <= c <= N
        c_p.append(mont_mul(c, r_sq, N, omega)[0])      # Store c * r_sq mod N
        c_cur.append(mont_L2R_exp(c_p[i], d, N, r_sq, omega)) # Calculate and Store

        time, test_message = Interact(c)    # Interact using random Ciphertext
        times.append(time)                 # Store time
                             # Store

    return times, c_p, c_cur, c, test_message


# Generate random Ciphertexts 0 <= c <= N
def Generate_Ciphertexts(N) :
    ciphertexts = []
    for i in range(13000):
        ciphertexts.append(random.randint(0, N))
    return ciphertexts

def get_avg(values):
    return sum(values) // len(values)


def Attack ( N , e ) :
    # Initialise Montgomery Params
    omega, r_sq = mont_omega(N), mont_r_sq(N)

    c_times, c_p, c_cur, test_cipher, test_message = generate_cs(N, d, r_sq, omega)


    d = 1
    print "Testing key bits"
    for n in range( 0, w) :  # For each bit in private exponent d
        is0, not0, is1, not1, c0, c1 = [], [], [], [], [], []
        for i, c in enumerate(c_p):
            TEMP = mont_L2R_exp(c, d, N, r_sq, omega)
            flag0, flag1, ci_0, ci_1 = next_bit_check(c,N,omega,TEMP)
            c0.append(ci_0)
            c1.append(ci_1)

            if flag0 :
                is0.append(c_times[i])
            else :
                not0.append(c_times[i])
            if flag1 :
                is1.append(c_times[i])
            else :
                not1.append(c_times[i])

        # Calculate the distinguisher
        diff0 = get_avg(is0) - get_avg(not0)
        diff1 = get_avg(is1) - get_avg(not1)

        # Statistically guess a bit
        # If there is no difference, regenerate all messages and try this bit again
        if diff0 > diff1:
            d <<= 1
            c_cur = c0
        elif diff1 > diff0:
            d = (d << 1) + 1
            c_cur = c1
        else:
            print "Can't distinguish a bit"
            print "Bit 0: %d" % diff0
            print "Bit 1: %d" % diff1
            print "Regenerating Messages"
            c_times, c_p, c_cur, num_interactions, test_cipher, test_message = generate_cs(N, d, r_sq, omega)

        print "Guessing bit %d, Key: %X" % (n, d)
        # Test if we have recovered the key by decrypting a ciphertext
        # This is done by bruteforcing the final bit, as we can't exploit
        # the square in the next round due to there not being another round
        if pow(test_cipher, d << 1, N) == test_message:
            d <<= 1
            break
        elif pow(test_cipher, (d << 1) + 1, N) == test_message:
            d = (d << 1) + 1
            break

    # Print results
    print "Key Recovered"
    print "Key: %X" % d
    print "Message decrypted by key: %X" % pow(test_cipher, d, N)
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














