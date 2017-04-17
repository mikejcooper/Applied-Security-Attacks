import subprocess
import sys
import random

import crypto.app
from CryptoPlus.Cipher import AES

if ( __name__ == "__main__" ) :
    # # Produce a sub-process representing the attack target.
    # target = subprocess.Popen( args   = sys.argv[ 1 ],
    #                          stdout = subprocess.PIPE,
    #                          stdin  = subprocess.PIPE )
    #
    # # Construct handles to attack target standard input and output.
    # target_out = target.stdout
    # target_in  = target.stdin

    # Generate random 128-bit ciphertext
    c = random.getrandbits(128)

    key = (('2b7e151628aed2a6abf7158809cf4f3c').decode('hex'), ('2b7e151628aed2a6abf7158809cf4f3c').decode('hex'))

    plaintext1 = ('6bc1bee22e409f96e93d7e117393172a').decode('hex')


    cipher = AES.new(key, AES.MODE_XTS)

    ciphertext = cipher.encrypt(plaintext1)

    print (ciphertext).encode('hex')


    decipher = AES.new(key, AES.MODE_XTS)
    deciphertext = decipher.decrypt(ciphertext)

    print (deciphertext).encode('hex')



    plaintext = '6bc1bee22e409f96e93d7e117393172a'

    ciphertext = '55ece01bd0b359d2f12b0a01fcab5be2'

    key = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c'

