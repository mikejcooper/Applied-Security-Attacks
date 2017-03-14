import hashlib
import Crypto.Cipher.AES as AES
import binascii

import math


def AES_check( m, c, k ) :
    c1 = AES.new( HexToByte(k) ).encrypt( HexToByte(m) )
    if HexToByte(c) == HexToByte(c1):
        return True
    else :
        return False

def AES_1_Block(text):
    return hashlib.md5(text).digest()

def AES_example():
    k = 'CB6818217807A5E2599A286817349133'
    k = AES_1_Block("This is my password")
    m = AES_1_Block("hello world")
    c = AES.new(k).encrypt(m)

    print AES_check(m, c, k)


# Convert 128 bit input into 4x4 State Matrix
def State_Matrix4x4(i_128) :
    return [ int(i_128[i:i + 2], 16) for i in range(0, len(i_128) - 1, 2) ]

def Print_SQ_Matrix(matrix, form) :
    sqrt = int(math.sqrt(len(matrix)))
    for i in range(0,sqrt):
        for m in matrix[i*sqrt : i*sqrt + sqrt] :
            if form == 'hex':
                print "%.2X " % m,
            elif form == 'int':
                print "%.3d " % m,
            else :
                Exception("Print_SQ_Matrix: Argument 2: 'form' incorrect" )
        print

# Convert Byte (4 bit) string to Hex (2 bit) string
def ByteToHex(byte_string) :
    if len(byte_string) <= 16:
        return binascii.hexlify(byte_string).zfill(32)
    else :
        return byte_string.zfill(32)

# Convert Hex (2 bit) string to Hex (4 bit) string
def HexToByte(hex_string) :
    if len(hex_string) <= 16:
        return hex_string.zfill(16)
    else :
        return hex_string.decode('hex').zfill(16)

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


# Convert to Hex string
def toHex(X):
    if isinstance(X, ( int, long )):
        return "%X\n" % X
    elif X == '':
        return 0
    else:
        return X.encode('hex')
