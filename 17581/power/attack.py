import hashlib
import sys, subprocess
from math import log,ceil

ORACLE_QUERIES = 0

# Expected label l and ciphertext c as octet strings
def Interact( fault, m ) :
    # Send (fault, message) to attack target.
    target_in.write( "%s\n" % ( fault ) )
    target_in.write( "%s\n" % ( i2osp(m) ) )
    target_in.flush()
    # From Oracle: 1-block AES ciphertext (represented as an octet string)
    c = target_out.readline().strip()
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return c


def playground():
    print "hey"
    #        r, f, p, i, j
    fault = ",,,,"
    m = 12345
    print Interact(m)





















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


