import hashlib
import sys, subprocess
from math import log,ceil

import time

LT_B = 2          # Less than B
GT_OR_EQ_B = 1    # Greater than or equal to B
ORACLE_QUERIES = 0

def Read_Params( file ) :
    # Read RSA modulus N
    N = file.readline().strip()
    # RSA public exponent e
    e = file.readline().strip()
    # Read RSAES-OAEP label l
    l = file.readline().strip()
    # RSAES-OAEP ciphertext c
    c = file.readline().strip()
    return ( N, e, l , c )

def Initialise_Input( N, e, l , c ) :
    N = os2ip(N)
    e = os2ip(e)
    c = os2ip(c)
    l = os2ip(l)
    k = int(ceil(log(N, 256)))  # Byte Length of N
    B = pow(2, 8 * (k - 1))
    return ( N, e, l, c, B, k )

# Expected label l and ciphertext c as octet strings
def Interact( l, c ) :
    # Send (l,c) to attack target.
    target_in.write( "%s\n" % ( i2osp(l) ) )
    target_in.write( "%s\n" % ( i2osp(c) ) )
    target_in.flush()
    # Receive A from attack target.
    A = int( target_out.readline().strip() )
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return A

def RSAES_OAEP_DECRYPT(N, e, l, c, B, k):
    # 2.
    EM = RSA_Decryption(N, e, l, c, B, k)
    print "Encoded Message:  " + EM
    # 3.
    Message = EME_OAEP_Decoding(EM, l, k)
    return Message

def pow_mod(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def RSA_Decryption(N, e, l, c, B, k):
    # a.
    # Convert the Ciphertext C to an integer Ciphertext representative c
    c = os2ip(c)

    # b.
    # Perform Chosen Ciphertext Attack to retrieve m
    m = CCA_Attack(N, e, l, c, B)

    # Check recovered m is correct: m^e mod N == c
    if pow( m , e , N ) == c  :
        print "* CCA Attack Successfully Recovered Encoded Message *"
    else :
        print "* CCA Attack Unsuccessful: Error *"

    # c.
    # Convert the message representative m to an encoded message EM of length k octets
    EM = I2OSP( os2ip(m) , k)
    return EM

# Chosen Ciphertext Attack
# Reference: "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0" - James Manger
def CCA_Attack(N, e, l , c, B) :
    print "Chosen Cipher Text Attack Stage 1 ..."
    f1 = CCA_Stage1(N, e, l, c)
    print "Chosen Cipher Text Attack Stage 2 ..."
    f2 = CCA_Stage2(N, e, l, c, B, f1)
    print "Chosen Cipher Text Attack Stage 3 ..."
    m = CCA_Stage3(N, e, l, c, B, f2)
    return os2ip(m)

def CCA_Stage1(N, e, l, c):
    f1 = 2                                                      # (1.1)
    while(True):
        c_new = ( c * pow( f1 , e , N ) ) % N                   # (1.2)
        c_new = Padding( c, c_new )
        error = Interact( l , c_new )
        if error == LT_B :                                      # (1.3a) RANGE: [0,B)       0  <= f1 * m  < B
            f1 = f1 << 1
        elif error == GT_OR_EQ_B:                               # (1.3b) RANGE: [B,2B)      B  <= f1 * m < 2B,   where 2B < N
            break
        else:
            raise Exception("CCA_Stage1 Interaction output not within bounds. Error = " + str(error))
    return f1

def CCA_Stage2(N, e, l, c, B, f1):
    f2 = Divide_Floor( (N + B) , B ) * (f1 / 2)                 # (2.1) RANGE: [B/2,B)      B/2 <= f2 / 2 * m < B
    while(True):
        c_new = ( c * pow( f2 , e , N ) ) % N                   # (2.2) RANGE: [N/2,N+B)    N/2 <= f2 * m < N + B
        c_new = Padding( c, c_new )
        error = Interact( l , c_new )
        if error == GT_OR_EQ_B:                                 # (2.3a) RANGE: [N/2,N)     N/2 <= f2 * m  < N
            f2 += f1 / 2
        elif error == LT_B :                                    # (2.3b) RANGE: [N,N+B)     N   <= f2 * m  < N + B
            break
        else:
            raise Exception("CCA_Stage2 Interaction output not within bounds. Error = " + str(error))
    return f2

def CCA_Stage3(N, e, l, c, B, f2):
    m_max = Divide_Floor( (N + B)  , f2 )                       # (3.1)  Top of range for m
    m_min = Divide_Ceil( N , f2 )                               # (3.1)  Bottom of range for m
    while m_max != m_min :
        previous = (m_max, m_min)                               # Used for Infinity check
        f_tmp = Divide_Floor( 2*B , (m_max - m_min) )           # (3.2)
        i = Divide_Floor( f_tmp * m_min , N )                   # (3.3)
        f3 = Divide_Ceil(i * N, m_min)                          # (3.4)
        c_new = (c * pow(f3, e, N)) % N
        c_new = Padding( c, c_new )
        error = Interact( l, c_new )
        if error == GT_OR_EQ_B:                                 # (3.5a)  RANGE: [i*N,i*N+B)     i*N     <= f3 * m  < i*N + B
            m_min = Divide_Ceil((i * N + B), f3)
        elif error == LT_B:                                     # (3.5b)  RANGE: [i*N+B,i*N+2B)  i*N + B <= f3 * m  < i*N + 2B
            m_max = Divide_Floor((i * N + B), f3)
        else:
            raise Exception("CCA_Stage3 Interaction output not within bounds. Error = " + str(error))
        # Infinity check
        if previous == (m_max, m_min):
            raise Exception("CCA_Stage3 Infinite loop")
    return m_min

# Reference: "Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1" - Section 7.1.2
def EME_OAEP_Decoding(EM, l, k):
    # a.
    # Set Label - Byte string
    L = (i2osp(l).decode('hex'))
    # Hash Label
    hashObject = hashlib.sha1(L)
    # Hash of L as hex string
    lHash = hashObject.hexdigest()
    # Length of lHash in octets
    hLen = hashObject.digest_size

    # b.
    # Separate the encoded message EM into a single octet Y, an octet string
    # maskedSeed of length hLen, and an octet string maskedDB of length k - hLen - 1 as
    # EM = Y | | maskedSeed | | maskedDB.
    Y, maskedSeed, maskedDB = EM[:2], EM[2:(2 * hLen + 2)], EM[(2 * hLen + 2):]

    # c.
    seedMask = MGF1(maskedDB, hLen)

    # d.
    seed = XOR_OCT( maskedSeed , seedMask )

    # e.
    dbMask = MGF1(seed, k - hLen - 1)

    # f.
    DB = XOR_OCT( maskedDB , dbMask )
    print "DB (Data Block):  " + DB

    # g.
    # DB =      lHash_   ||    PS   ||   0x01   ||    M
    # Lengths: [2*hLen]    [Unknown]     [1]      [Unknown]
    # Separate DB into an octet string lHash_ of length hLen, a (possibly empty)
    # padding string PS consisting of octets with hexadecimal value 0x00 and a message M

    # Find the position of the 0x01 octet after Hashed Label information (0x00's)
    index = DB.find("01", 2*hLen)

    lHash_, PS, OxO1, M = DB[:2*hLen], DB[2*hLen:index], DB[index:index+2], DB[index+2:]

    # Check for errors
    # If lHash does not equal lHash_
    if not Compare_OCT(lHash, lHash_):
        raise Exception("lHash does not equal lHash\'.")
    # If Y is nonzero
    if not Compare_OCT(Y, 0):
        raise Exception("Y is nonzero.")
    # If there is no octet with value 0x01
    if index == -1:
        raise Exception("0x01 was not found.")
    return M, lHash

# MGF1 is a Mask Generation Function based on a hash function.
def MGF1(mgfSeed, maskLen) :
    # 1.
    if maskLen > pow(2,32) :
        raise Exception("mask too long")

    # 2.
    # Let T be the empty octet string
    T = ''
    # Length in octets
    hLen = hashlib.sha1(T).digest_size

    # 3.
    # For counter from 0 to \ceil (maskLen / hLen) - 1
    for counter in range(0, Divide_Ceil(maskLen, hLen)) :
        # 3.a.
        # Convert counter tp an octet string C of length 4 octets
        C = I2OSP(counter, 4)

        # 3.b.
        # Concatenate the hash of the seed mgfSeed and C to the octet string T.
        #  T = T || Hash(mgfSeed || C)
        T = T + hashlib.sha1((str(mgfSeed) + C).decode('hex')).hexdigest()

    # 4.
    # Output the leading maskLen octets of T as the octet string mask.
    return T[:2*maskLen]

# Converts the integer x to its big-endian representation of length x_len.
def I2OSP(x, xLen = -1) :
    # 1.
    if x >= pow( 256, xLen ) :
        raise Exception("integer too large")

    # 2.
    # Write the integer x in its unique xLen-digit representation in base 256
    x = format(x, 'X')

    # 3.
    # If x < 256^(xLen-1) one or more leading digits will be zero.
    # xLen = size in octets = 2 hex digits
    return x.zfill(2*xLen)

# Octal String to Integer
def os2ip(X):
    if isinstance(X, ( int, long )):
        return X
    elif X == '':
        return 0
    else:
        return int(X, 16)

# Integer to Octal String
def i2osp(X):
    if isinstance(X, basestring):
        return X.upper()
    else:
        return format(X, 'X')

def XOR_OCT( X, Y ):
    return i2osp( os2ip(X) ^ os2ip(Y) )

def Compare_OCT( X, Y):
    if os2ip(X) == os2ip(Y) :
        return True
    else :
        return False

def Padding(original , current) :
    desired_length = len(i2osp(original))
    current = i2osp(current)
    return current.zfill(desired_length)

def Divide_Ceil(x, y):
    return -(-x // y)

def Divide_Floor(x, y):
    return x // y



if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read from file
    (N, e, l, c) = Read_Params(open(sys.argv[2], 'r'))

    # ( Modulus, Public exponent, Label, Ciphertext, B = 2^(8*(k-1)), #N Bytes)
    (N, e, l, c, B, k) = Initialise_Input(N, e, l, c)

    start = time.time()

    # RSA OAEP Decryption
    Message, lHash = RSAES_OAEP_DECRYPT(N, e, l, c, B, k)

    end = time.time()

    print "Hashed Label:     " + i2osp(lHash)
    print "Decryption time:  %ds" % (end - start)
    print "\nMessage:          " + i2osp(Message)
    print "Oracle uses:      " + str(ORACLE_QUERIES)



