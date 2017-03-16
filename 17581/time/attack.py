import sys, subprocess
import random
import time
from montgomery import *
from error import Errors
from scipy.stats import ttest_ind, ttest_ind_from_stats, stats

ORACLE_QUERIES = 0
SAMPLE_SIZE = 5000

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

def Generate_Red_Dec_Time(N, r_sq, omega, d) :
    mont, decryption, times = [], [], []
    for i in range(SAMPLE_SIZE):
        c = random.randint(0, N)                                        # Generate random Ciphertexts 0 <= c <= N
        mont.append(mont_mul(c, r_sq, N, omega)[0])                     # Convert Ciphertexts into Montgomery Domain
        decryption.append(mont_L2R_exp(mont[i], d, N, r_sq, omega))     # Generate 1st Decryption Ciphertexts using initial d = 1 value
        times.append(Interact(c)[0])                                    # Generate Times from oracle interaction
    return ( mont, decryption, times )

# Create test Message and Ciphertext
def Create_Test():
    message = toHexInt("Hello World")
    ciphertext = pow(message, e, N)
    return message, ciphertext

def get_avg(values):
    return sum(values) // len(values)

# Perform independent statistical test
def get_difference(X, Y):
    return 1 - stats.ttest_ind(X, Y)[1]


# Reference: http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=E82828DA2379558D3EC51809A2E4DFDC?doi=10.1.1.28.2496&rep=rep1&type=pdf
def Attack ( N , errors ) :
    # Initialise Params
    test_message, test_cipher = Create_Test()
    omega, r_sq, d = mont_omega(N), mont_r_sq(N), 1     # Montgomery Params and d = 1
    data = Generate_Red_Dec_Time(N, r_sq, omega, d)     # Fetch data for time attack
    c_mont = data[0]                                    # Ciphertexts in Mongomery Domain,
    c_decryption = data[1]                              # Ciphertexts decryption using d = 1
    c_times = data[2]                                   # Time for each c to decrypt

    print "Decrypting bit %d, Private Key (Binary): %s" % (0, bin(d)[2:])

    n = 0
    while n < BITS :                           # For each bit in private exponent d
        is0, not0, is1, not1, c0, c1 = [], [], [], [], [], []
        for i, c in enumerate(c_mont):
            # Check if reduction is required for next bit (0 or 1) - Attack the square
            flag0, flag1, ci_0, ci_1 = next_bit_check( c , N, omega, c_decryption[i])

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

        errors.Update(diff0, diff1, n, c0, c1)

        # [A] Error Testing
        if errors.ErrorIncreaseSample:                                      # Too many uncertain bits in attack, double sample size
            print "Uncertainty too high. Increasing Sample Size..."
            globals().update(SAMPLE_SIZE = SAMPLE_SIZE + SAMPLE_SIZE/2)
            print SAMPLE_SIZE
        if errors.ErrorResample:                                            # Too many uncertain bits in attack, resample with new ciphertexts
            print "Uncertainty too high. Resampling..."
            d, n = 1, 0
            c_mont, c_decryption, c_times = Generate_Red_Dec_Time(N, r_sq, omega, d)
        elif errors.ErrorRevert:                                            # Go back to last uncertain bit and change decision
            LastCertainBit = errors.RevertToBitX
            d = d >> (n - LastCertainBit - 1)                               # Revert back version of d with uncertain bit
            d = d ^ 1                                                       # Invert uncertain bit
            c_decryption = errors.CipherithRound[LastCertainBit]            # Revert ciphertexts to that rounds ciphertexts
            print "Uncertain about current bit: " + str(n) + \
                  ". Reverting to previous uncertainty at bit: " + str(LastCertainBit + 1)
            n = LastCertainBit                                              # Revert round number
        else :
            if errors.ErrorUncertain:                                       # Not certain about current bit, diff1 - diff0 is small
                print "Uncertain about current bit: " + str(n + 1)
            # Statistical prediction
            if diff0 > diff1:
                d <<= 1                                                     # ith bit, di = 0
                c_decryption = c0                                           # Correctly decrypted ciphertexts up to current iteration
            else :
                d = (d << 1) + 1                                            # ith bit, di = 1
                c_decryption = c1                                           # Correctly decrypted ciphertexts up to current iteration

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
        elif errors.FailedDecryptionNum > 4 :
            print "** Decryption Failed... **"
            break
        elif n == BITS - 1:
            print "Decryption Failed, try again..."
            errors.FailedDecryption = True
            errors.FailedDecryptionNum += 1
            d, n = 1, 0
            c_mont, c_decryption, c_times = Generate_Red_Dec_Time(N, r_sq, omega, d)


        n += 1

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

    # Initialise Errors
    errors = Errors(N)

    print "** Start Timing Attack **\n"

    start = time.time()

    # Timing Attack
    PrivateKey = Attack(N, errors)

    end = time.time()


    if check(PrivateKey, e, N) :
        print "\n** Key Recovery Successful **"
    else :
        print "\n** Key Recovery Unsuccessful: Error **"

    print "Private Key (Binary): %s" % bin(PrivateKey)[2:]
    print "Decryption time: %ds" % (end - start)
    print "\nPrivate Key (Hex):    %X" % PrivateKey
    print "Oracle uses:", str(ORACLE_QUERIES)

















