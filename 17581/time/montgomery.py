import math
# from attack import BITS, b, mask

# SET AT RUNTIME:
import time

BITS = 0  # X-Bit: mpz_size(N) * 4
b = 0     # Montgomery Multiplication
mask = 0  # pow(2,BITS) - 1 , max number before integer overflow

# Initialise Global variables, dependent on size of N (allows for variable X-Bit target processor)
def Initialise_Globals_Mont( N ) :
    globals().update( BITS = mpz_size(N) * 4 )
    globals().update( b = 1 << BITS )
    globals().update( mask = pow(2,BITS) - 1 )

# Helper function to initialise Montgomery variables
def mp_bits_per_limb(N):
    return mpz_size(N) * 4

def mpz_size(N):
    return Divide_Ceil(len("%X" % N), 16)

def mont_omega (N) :
    omega = 1
    for i in range(1, mp_bits_per_limb(N)):
        omega = (omega * omega * N) & (b - 1)
    return (b - omega)

def mont_r_sq (N) :
    r_sq = 1
    for i in range(2 * mp_bits_per_limb(N) * mpz_size(N)):
        r_sq = (r_sq + r_sq) % N
    return r_sq

def mpz_getlimbn(x, i):
    return (x >> BITS * i) & mask

# Montgomery multiplication
# r = a.b mod N
# Returns result and boolean to indicate whether a reduction was required
def mont_mul(x, y, N, omega):
    r = 0
    for i in range(0, int(mpz_size(N))):
        x0 = mpz_getlimbn(x, 0)             # 0-th limb a
        r0 = mpz_getlimbn(r, 0)             # 0-th limb r
        yi = mpz_getlimbn(y, i)             # i-th limb y
        u = (r0 + yi * x0) * omega % b      # u = (r0 + yi.x0).omega (mod b)
        r = (r + yi * x + u * N) / b        # r = (r + yi.x + u.N) / b
    if (r >= N) :
        r = r - N
        return r, True
    else :
        return r, False

# Perform Montgomery Reduction
def mont_red(t, N, omega):
    for i in range(mpz_size(N)):
        ti = mpz_getlimbn(t, i)                        # get ith limb
        u  = ti * omega % b
        t  = t + u * (N << i * mp_bits_per_limb(N))     # t = t + u.N.(b ^ i)
    t >>= (mp_bits_per_limb(N) * mpz_size(N))          # t = t / b^size(N)
    if t > N:
        return t - N
    else:
        return t

# Left-to-right binary exponentiation, optimised with Montgomery Multiplication
# b ^ e (mod N)
def mont_L2R_exp(b, e, N, rho_2, omega):
    r = mont_red(rho_2, N, omega)
    bits_exp = int(math.log(e, 2))
    for i in range(bits_exp, -1, -1):           # For each bit in exponent
        r = mont_mul(r, r, N, omega)[0]         # r = r * r (mod N)
        if (e >> i) & 1:                        # if left most bit is 1
            r = mont_mul(r, b, N, omega)[0]     # r = r * b (mod N)
    return r

# Check if reduction is required for next bit (0 or 1) in private exponent
def next_bit_check(b, N, omega, c):
    c0, _      = mont_mul(c, c, N, omega)            # Check reduction if 0
    _ , flag0  = mont_mul(c0, c0, N, omega)          # Check reduction if 0

    c1, _      = mont_mul(c0, b, N, omega)           # Check reduction if 1
    _ , flag1  = mont_mul(c1, c1, N, omega)          # Check reduction if 1
    return (flag0, flag1, c0, c1)


#####################
# Utility Functions #
#####################

def Divide_Ceil(x, y):
    return -(-x // y)

def pow_mod(x, y, z):
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

def check(d, e, N):
    message_original = toHexInt("Hello World")
    ciphertext = pow_mod(message_original, e, N)
    message_decrypted = pow_mod(ciphertext, d, N)
    if(message_original == message_decrypted):
        return True
    else :
        return False



