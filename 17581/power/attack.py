import hashlib
import sys, subprocess

from Utils import *

ORACLE_QUERIES = 0

# Expected label l and ciphertext c as octet strings
def Interact( fault, m ) :
    # Send (fault, message) to attack target.
    target_in.write( "%s\n" % ( fault ) )
    target_in.write( "%s\n" % ( i2osp(m) ) )
    target_in.flush()
    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    _traces = target_out.readline().strip()[:None]

    if _traces[-1] == ',' or _traces[-1] == ' ':
        _traces = _traces[:-1]

    __traces = _traces.split(',')
    traces = []
    for i in __traces:
        traces.append(int(i))
    # Receive decryption from attack target
    dec = target_out.readline().strip()
    # return (traces, dec)


    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return m

# Expected label l and ciphertext c as octet strings
def Interact( j, i, c, k) :
    # Send (fault, message) to attack target.
    target_in.write( "%s\n" % ( j ) )
    target_in.write( "%s\n" % ( (i) ) )
    target_in.write("%s\n" % ( (c) ))
    target_in.write("%s\n" % ( (k) ))
    target_in.flush()

    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    _traces = target_out.readline()

    # Receive decryption from attack target
    dec = target_out.readline().strip()

    return (_traces, dec)


def playground():
    print "hey"
    #        r, f, p, i, j

    k = AES_1_Block("This is my password")
    m = AES_1_Block("hello world")
    c = AES.new(k).encrypt(m)

    k = ByteToHex(k) + ByteToHex(k)
    c = ByteToHex(c)
    m = ByteToHex(m)

    if AES_check(m,c,k) :
        print "hello"

    j = "12"
    i = "CB6818217807A5E2599A286817349133"

    (t,m_dec) = Interact(j, i, c, k)

    m_dec == m




















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


