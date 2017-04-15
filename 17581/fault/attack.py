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
    c = target_out.readline().strip()
    globals().update(ORACLE_QUERIES = ORACLE_QUERIES + 1)
    return c



def playground():
    #        r, f, p, i, j
    # fault = "8,3,0,0,0"
    fault = ""
    m = ByteToHex(AES_1_Block("hello world"))
    c = Interact(fault, m)

    k = 'CB6818217807A5E2599A286817349133'

    Print_SQ_Matrix(State_Matrix4x4(c), 'hex')

    print AES_check(m,c,k)







if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    playground()


