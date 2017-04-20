import sys, subprocess
from hashlib import sha1

# Error codes
SUCCESS = 0
ERROR1  = 1
ERROR2  = 2

# Read Public Key and Ciphertext from User.param and calculate k and B
def readParams( file ) :
    global N, k, B, e, c, count_interactions

    # Read modulus N
    temp = file.readline()
    N = int(temp, 16)

    # Calculate k, the byte length of N
    # k = ceil[log 256 N]
    # k = (number of octet in N) / 2
    k = len(temp)/2

    # Calculate B = 2^(8*(k-1))
    B =  pow(2, 8*(k-1))

    # Read public exponent e
    e = int(file.readline(), 16)

    # Read ciphertext c
    c = int(file.readline(), 16)

    count_interactions = 0

    file.close()

def interact( ciphertext ) :
    # count interactions
    global count_interactions
    count_interactions += 1

    # Send ciphertext to attack target. Ciphertext length must me 256.
    target_in.write( "%s\n" % ("%X" % ciphertext ).zfill(256) ) ; target_in.flush()

    # Receive ( t, r ) from attack target.
    return int( target_out.readline().strip() )

def floorDivision(a, b) :
    r = a%b
    return (a-r)/b

def ceilDivision(a, b):
  r = a%b
  if r > 0 :
    return (a-r)/b +1
  else :
    return (a-r)/b


def oracle(f) :
    result = pow(f , e, N)
    result = result * c
    result = result % N
    return interact(result)

def Step1() :
    f1 = 2

    # Try f1 with oracle
    errCode = oracle(f1)

    while errCode == ERROR2 :
        f1 = f1 * 2
        errCode = oracle(f1)

    # Step 1.3b
    # Check if errCode indicates "<B", if not something went wrong.
    if errCode != ERROR1 :
        raise Exception("Something went wrong!")

    return f1

def Step2(f1) :
    temp = f1 / 2
    f2 = floorDivision((N+B), B) * temp

    # Try f2 with oracle
    errCode = oracle(f2)

    while errCode == ERROR1 :
        f2 = f2 + temp
        errCode = oracle(f2)

    # check if the oracle indicates "<B", if not something went wrong
    if errCode != ERROR2 :
        raise Exception("Something went wrong!")

    return f2

def Step3(f2) :
    # 3.1
    mmin = ceilDivision(N,f2)
    mmax = floorDivision((N+B), f2)

    while mmin != mmax :
        # 3.2
        ftmp = floorDivision((2*B) , (mmax-mmin))

        # 3.3
        i = floorDivision((ftmp*mmin) , N)
        i_n = i * N

        # 3.4
        f3 = ceilDivision(i_n, mmin)
        #Try with oracle
        errCode = oracle(f3)

        if errCode == ERROR1 :
            # 3.5a
            mmin = ceilDivision((i_n + B) , f3)
        elif errCode == ERROR2 :
            # 3.5b
            mmax = floorDivision((i_n + B) , f3)
        else:
            raise Exception("Something went wrong!")

    return ("%X" % mmin).zfill(256)

# Integer to octet string primitive
# Converts a nonnegative integer to an octet string of a specified length.
# 4.1
def I2OSP(x, xLen) :
    # 1.
    if x >= 256**xLen :
        raise Exception("integer too large")

    # 2.
    # Write the integer x in its unique xLen-digit representation in base 256
    # Convert to hex, group by two.
    x = "%X" % x
    # If x < 256^(xLen-1) one or more leading digits will be zero.
    # xLen is size in octets, octet = 2 hex digits
    return x.zfill(2*xLen)

# Mask generation function
# Appendix B.2.1 MGF1
def MGF(mgfSeed, maskLen) :
    # 1.
    if maskLen > 2**32 :
        raise Exception("mask too long")

    # 2.
    # Let T be the empty octet string
    T = ''
    hLen = sha1(T).digest_size

    # 3.
    for counter in range(0, ceilDivision(maskLen, hLen)) :
        # 3.a.
        # Convert counter tp an octet string C of length 4 octets
        C = I2OSP(counter, 4)

        # 3.b.
        # Concatenate the hash of the seed mgfSeed and C to the octet string T.
        T += sha1((str(mgfSeed)+C).decode('hex')).hexdigest()

    # Check that T is at least 2*maskLen hex digits long
    if len(T) < 2*maskLen :
        raise Exception("T is too short.")

    # Output the leading maskLen octets of T as the octet string mask.
    return T[:2*maskLen]

def EME_OAEP_Decode(EM) :
    # a.
    # Empty label L
    L = ""
    hashObject = sha1(L)
    # Get the hash of L as hex string
    lHash = hashObject.hexdigest()
    # Find length of lHash in octets
    hLen = hashObject.digest_size

    # b.
    # Separate the encoded message into a single octet Y, an octet string maskedSeed
    # of length hLen, and an octet string maskedDB of length k-hLen-1, k = length of
    # ciphertext
    Y = EM[:2]
    maskedSeed = EM[2:(2*hLen+2)]
    maskedDB = EM[(2*hLen+2):]

    # c.
    seedMask = MGF(maskedDB, hLen)

    # d.
    seed = "%X" % ( int(maskedSeed, 16) ^ int(seedMask, 16) )

    # e.
    dbMask = MGF(seed, k-hLen-1)

    # f.
    DB = "%X" % ( int(maskedDB, 16) ^ int(dbMask, 16) )

    # g.
    # DB = lHash_ || PS || 0x01 || M
    # Separate DB into an octet string lHash_ of length hLen, a (possibly empty)
    # padding string PS consisting of octets with hexadecimal value 0x00 and a
    # message M

    lHash_ = DB[:2*hLen]

    # Find the position of the 0x01 octet, started searching after the first 2*hLen digits
    index = DB.find("01", 2*hLen)

    PS = DB[2*hLen:index]

    OXO1 = DB[index:index+2]

    M = DB[index+2:]

    # Check for errors
    # If there is no octet with value 0x01
    if index == -1 :
        raise Exception("No octed with value 0x01 was found.")
    # If lHash does not equal lHash_
    if int(lHash, 16) != int(lHash_, 16) :
        raise Exception("lHash does not equal lHash\'.")
    # If Y is nonzero
    if int(Y, 16) != 0 :
         raise Exception("Y is nonzero.")

    # Output the message
    return M

def attack() :
    # Recover the encoded message (EM) using Manger's attack
    f1 = Step1()
    f2 = Step2(f1)
    EM = Step3(f2)

    print "Recovered encoded message: ", EM

    # Recover the message from the encoded message
    M = EME_OAEP_Decode(EM)

    print "Recovered message: ", M

    print "Number of interactions with the attack target: ", count_interactions

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Read public parameters
  file = open(sys.argv[2], 'r')
  readParams(file)

  # Execute a function representing the attacker.
  attack()
