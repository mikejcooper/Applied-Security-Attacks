import sys, subprocess
import random
from timeit import default_timer
from montgomery import *

ORACLE_QUERIES = 0

# SET AT RUNTIME:
BITS = 0  # X-Bit: mpz_size(N) * 4
b = 0     # Montgomery Multiplication
mask = 0  # pow(2,BITS) - 1 , max number before integer overflow


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

# Initialise Global variables, dependent on size of N (allows for variable X-Bit target processor)
def Initialise_Globals( N ) :
    globals().update( BITS = mpz_size(N) * 4 )
    globals().update( b = 1 << BITS )
    globals().update( mask = pow(2,BITS) - 1 )
    Initialise_Globals_Mont(N)

def Interact( c ) :
    # Send Ciphertext c as Hexidecimal string to attack target.
    target_in.write( "%s\n" % ( toHex(c) ) )
    target_in.flush()
    # Receive ( Time t, Message m ) from attack target.
    t = int(target_out.readline().strip())
    m = int(target_out.readline().strip(), 16)
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return ( t, m )

# Generate random Ciphertexts 0 <= c <= N
def Generate_Ciphertexts(N) :
    ciphertexts = []
    for i in range(13000):
        ciphertexts.append(random.randint(0, N))
    return ciphertexts

def Generate_Red_Dec_Time(ciphertexts, N, r_sq, omega, d) :
    reduced, decryption, times = [], [], []
    for i, c in enumerate(ciphertexts):
        reduced.append(mont_mul(c, r_sq, N, omega)[0])                  # Generate Reduced Ciphertexts using r_sq
        decryption.append(mont_L2R_exp(reduced[i], d, N, r_sq, omega))  # Generate 1st Decryption Ciphertexts using initial d = 1 value
        times.append(Interact(c)[0])                                    # Generate Times from oracle interaction
    return ( reduced, decryption, times )

# Create test Message and Ciphertext
def Create_Test():
    message = toHexInt("Hello World")
    ciphertext = pow_mod(message, e, N)
    return message, ciphertext

def get_avg(values):
    return sum(values) // len(values)


def Attack ( N , e ) :
    # Initialise Params
    omega, r_sq, d = mont_omega(N), mont_r_sq(N), 1
    test_message, test_cipher = Create_Test()

    ciphertexts = Generate_Ciphertexts(N)
    c_reduced, c_decryption, c_times = Generate_Red_Dec_Time(ciphertexts, N, r_sq, omega, d)
    print "Decrypting bit %d, Private Key (Binary): %s" % (0, bin(d)[2:])

    for n in range( 0, 64 ) :  # For each bit in private exponent d
        is0, not0, is1, not1, c0, c1 = [], [], [], [], [], []
        for i, c in enumerate(c_reduced):
            # Check if reduction is required for next bit (0 or 1) in private exponent
            flag0, flag1, ci_0, ci_1 = next_bit_check( c , N, omega, c_decryption[i] )
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

        # Calculate differences
        diff0 = get_avg(is0) - get_avg(not0)
        diff1 = get_avg(is1) - get_avg(not1)

        # Statistical prediction
        # If there is no difference, regenerate and try again
        if diff0 > diff1:
            d <<= 1                 # ith bit, di = 0
            c_decryption = c0       # Correctly decrypted ciphertexts up to current iteration
        elif diff1 > diff0:
            d = (d << 1) + 1        # ith bit, di = 1
            c_decryption = c1       # Correctly decrypted ciphertexts up to current iteration
        else:
            print "Can't distinguish a bit. Trying again..."
            ciphertexts = Generate_Ciphertexts(N)
            c_reduced, c_decryption, c_times = Generate_Red_Dec_Time(ciphertexts, N, r_sq, omega, d)

        print "Decrypting bit %d, Private Key (Binary): %s" % (n+1, bin(d)[2:])
        # Test if private key has been found
        if pow(test_cipher, d << 1, N) == test_message:
            d <<= 1
            print "Decrypting bit %d, Private Key (Binary): %s" % (n+2, bin(d)[2:])
            break
        elif pow(test_cipher, (d << 1) + 1, N) == test_message:
            d = (d << 1) + 1
            print "Decrypting bit %d, Private Key (Binary): %s" % (n+2, bin(d)[2:])
            break
    return d



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

    # Initialise Global variables, dependent on size of N (allows for variable X-Bit target processor)
    Initialise_Globals(N)

    print "** Start Timing Attack **"

    # Timing Attack
    PrivateKey = Attack(N, e)

    if check(PrivateKey, e, N) :
        print "** Key Recovery Successful **"
    else :
        print "** Key Recovery Unsuccessful: Error **"

    print "Oracle uses:", str(ORACLE_QUERIES)
    print "Private Key (Binary): %s" % bin(PrivateKey)[2:]
    print "Private Key (Hex): %X" % PrivateKey















