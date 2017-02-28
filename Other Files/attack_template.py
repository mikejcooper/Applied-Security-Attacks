import sys, subprocess, os.path, math, hashlib

LESS_THAN_B = 2
GREATER_OR_EQ_B = 1


def interact(l, c):
    # Send l to attack target.
    target_in.write("%s\n" % (l));
    target_in.flush()
    # Send c to attack target.
    target_in.write("%s\n" % (c));
    target_in.flush()
    # Receive r from attack target.
    r = int(target_out.readline().strip())
    return r


def ceil_divide(x, y):
    return (x + (-x % y)) // y


def readConf(confName):
    pathStr = os.path.abspath(confName)
    with open(pathStr, "r") as f:
        n = f.readline().strip()
        e = f.readline().strip()
        l = f.readline().strip()
        c = f.readline().strip()
    return (n, e, l, c)


def zeroPad(hexString, expectedLength):
    zeros = expectedLength - len(hexString)
    for i in range(zeros):
        hexString = '0' + hexString
    return hexString


def step1(n, e, l, c):
    f1 = 2

    while True:
        c_modified = (c * pow(f1, e, n)) % n
        c_modified = zeroPad(format(c_modified, "X"), len(format(n, "X")))
        r = interact(l, c_modified)
        if r == LESS_THAN_B:
            f1 = f1 << 1
        elif r == GREATER_OR_EQ_B:
            break;
        else:
            raise Exception("Result other than 0 or 1, r = " + str(r))
    return f1


def step2(n, e, l, c, B, f1):
    f2 = ((n + B) / B) * (f1 / 2)
    while True:
        c_modified = (c * pow(f2, e, n)) % n
        c_modified = zeroPad(format(c_modified, "X"), len(format(n, "X")))
        r = interact(l, c_modified)
        if r == GREATER_OR_EQ_B:
            f2 = f2 + (f1 / 2)
        elif r == LESS_THAN_B:
            break
        else:
            raise Exception("Result other than 0 or 1, r = " + str(r))
    return f2


def step3(n, e, l, c, B, f2):
    m_min = ceil_divide(n, f2)
    m_max = (n + B) / f2
    k = 0
    last_round = (0, 0)
    while True:
        last_round = (m_max, m_min)

        f_tmp = (2 * B) / (m_max - m_min)
        i = (f_tmp * m_min) / n
        i_n = i * n
        f3 = ceil_divide(i_n, m_min)

        c_modified = (c * pow(f3, e, n)) % n
        c_modified = zeroPad(format(c_modified, "X"), len(format(n, "X")))
        r = interact(l, c_modified)
        k += 1
        if r == GREATER_OR_EQ_B:
            m_min = ceil_divide((i_n + B), f3)
        elif r == LESS_THAN_B:
            m_max = (i_n + B) / f3
        else:
            raise Exception("Result other than 0 or 1, r = " + str(r))
        if m_min == m_max:
            return (m_min, k)

        if last_round == (m_max, m_min):
            print "Breaking from infinte loop"
            break
    raise Exception("Message not found, limits did not converge.\nm_max = " + str(m_max) + "\nm_min = " + str(m_min))


## FUNCTIONS FROM PYTHON PCKS REPO

def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if x > 256 ** x_len:
        raise Exception("Integer too large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = h.decode('hex')
    return '\x00' * int(x_len - len(x)) + x


def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    '''
       Mask Generation Function v1 from the PKCS#1 v2.0 standard.
       mgs_seed - the seed, a byte string
       mask_len - the length of the mask to generate
       hash_class - the digest algorithm to use, default is SHA1
       Return value: a pseudo-random mask, as a byte string
       '''
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = ''
    for i in xrange(0, ceil_divide(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]


def string_xor(a, b):
    '''Computes the XOR operator between two byte strings. If the strings are
       of different lengths, the result string is as long as the shorter.
    '''
    return ''.join((chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)))


## END OF FUNCTIONS FROM PYTHON PCKS REPO

def OAEP_decode(m_hex, l):
    l_hash_object = hashlib.sha1(l)
    l_hash = l_hash_object.digest()
    l_hash = str(l_hash)
    hLen = len(l_hash)
    k = len("00" + m_hex) / 2

    m = i2osp(int(m_hex, 16), k)

    Y, maskedSeed, maskedDB = m[0], m[1:hLen + 1], m[1 + hLen:]

    seedMask = mgf1(maskedDB, hLen)

    seed = string_xor(maskedSeed, seedMask)

    dbMask = mgf1(seed, k - hLen - 1)
    DB = string_xor(maskedDB, dbMask)
    # print "Padded message:", DB.encode("hex")
    lHash = DB[0:hLen]
    m_zeros = DB[hLen:]
    m_start = 0
    for i in range(len(m_zeros)):
        if m_zeros[i] == '\x01':
            m_start = i + 1
            break
        elif m_zeros[i] != '\x00':
            raise Exception("Decryption Error")

    m = m_zeros[m_start:]
    return m.encode("hex")


if (__name__ == "__main__"):
    # Produce a sub -process representing the attack target.
    target = subprocess.Popen(args=os.path.abspath(sys.argv[1]), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in = target.stdin
    # Execute a function
    (n, e, l, c) = readConf(sys.argv[2])
    n = int(n, 16)
    e = int(e, 16)
    l = ""  # int(l, 16)
    ##l = str(int(l,16))
    c = int(c, 16)
    f1 = step1(n, e, l, c)
    k = int(math.ceil(math.log(n, 256)))
    B = pow(2, 8 * (k - 1))
    f2 = step2(n, e, l, c, B, f1)
    (m, k) = step3(n, e, l, c, B, f2)
    m_hex = format(m, "x")
    m = OAEP_decode(m_hex, l)
    print "Oracle uses:", str(k)
    print "Unpadded message:", format(int(m, 16), "X")