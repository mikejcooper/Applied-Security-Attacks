

class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False



def handle_errors(A):
    for case in switch(A):
        if case(0):
            print "Decryption successful"
            break
        if case(1):
            print "RSA decryption: Output is too large to fit into one fewer octets than the modulus."
            break
        if case(2):
            print "Plaintext validity checking mechanism fails:" + "\n  Either hashed label does not match OR octet '01' not found between padding and message."
            break
        if case(3):
            # Assumption: RSA public key (n, e) is valid
            print "Plaintext representative out of range" + ": 0 to N -1"
            case3();
            break
        if case(4):
            # Assumption: RSA private key K is valid
            print "Ciphertext representative out of range" + ": 0 to N -1"
            break
        if case(5):
            print "Length check failed:" + "\n  Either Message OR Label too long"
            break
        if case(6):
            print "Length check failed:" + "\n  Ciphertext does not match the length of N"
            break
        if case(7):
            print "Length check failed:" + "\n  Ciphertext does not match the length of the hash function output."
            break
        if case():  # default
            print "Abnormal error!"





def hex2int(hex) :
    return int(hex, 16)

def str2seq( x ) :
    return [ ord( t ) for t in x ]

def seq2str( x ) :
    return "".join( [ chr( t ) for t in x ] )





