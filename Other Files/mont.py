import sys, subprocess, os


def interact( l, c ) :
  # Send      G      to   attack target.
  target_in.write( "%s\n" % ( l ) ) ;
  target_in.write( "%s\n" % ( c ) ) ;
  target_in.flush()



  # Receive ( t, r ) from attack target.
  A = int( target_out.readline().strip() )

  return ( A )

def attack( l , c) :
  # Select a hard-coded guess ...
  # l = "248493"
  # c = "324"

  # ... then interact with the attack target.
  ( A ) = interact( l , c )

  # Print all of the inputs and outputs.
  print "G = %s" % ( l )
  print "t = %s" % ( c )
  print "r = %d" % ( A )



def params_in( file ) :
    # Read RSA modulus N
    N = int(file.readline().strip(), 16)
    # RSA public exponent e
    e = int(file.readline().strip(), 16)
    # Read RSAES-OAEP label l
    l = file.readline().strip()
    # RSAES-OAEP ciphertext c
    c = file.readline().strip()

    # # Read RSAES-OAEP label l
    # l = int(file.readline() , 16)
    # # RSAES-OAEP ciphertext c
    # c = int(file.readline() , 16)
    return ( N, e, l , c )


# Compute Montgomery rho
def getRho() :
    temp = 1
    while temp <= N :
        temp *= b
    return temp

# Compute Montgomery omega
def getOmega() :
    return (-number.inverse(N, rho)) % rho

# Compute Montgomery rho squared
def getRhoSq() :
    return pow(rho, 2, N)

# Get all Montgomery parameters
def montParam() :
    global rho, omega, rho_sq
    rho = getRho()
    omega = getOmega()
    rho_sq = getRhoSq()



if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Read public parameters
  N, e, l , c = params_in(open(sys.argv[2], 'r'));

  # Execute a function representing the attacker.
  attack( l, c )

  # print "Target material recovered: "
  # print "Total number of interactions with attack target: "
