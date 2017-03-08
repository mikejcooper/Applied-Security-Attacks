import hashlib
import sys, subprocess
import random
import struct
import Crypto.Cipher.AES as AES

ORACLE_QUERIES = 0

# Expected label l and ciphertext c as octet strings
def Interact( fault, m ) :
    # Send (fault, message) to attack target.
    target_in.write( "%s\n" % ( fault ) )
    target_in.write( "%s\n" % ( i2osp(m) ) )
    target_in.flush()
    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    c = target_out.readline().strip()

    x = [int(c[i:i + 2], 16) for i in range(0, len(c) - 1, 2)]

    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return c, x



def playground():
    print "hey"
    #        r, f, p, i, j
    fault = "0,0,0,0,0"
    m = (random.getrandbits(128))
    print i2osp(random.getrandbits(128))
    print Interact(fault, m)




def AES_check( message, ciphertext, key ) :
    c = AES.new(key).encrypt(message)
    if ciphertext == c:
        return True
    else :
        return False


def AES_example():
    key = "This is my password"
    message = "hello world"
    # 128 bit hash
    key_128 = hashlib.md5(key).digest()
    message_128 = hashlib.md5(message).digest()
    ciphertext = AES.new(key_128).encrypt(message_128)
    print AES_check(message_128, ciphertext, key_128)


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
        return X
    else:
        return format(X, 'X')


if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    playground()
    AES_example()


