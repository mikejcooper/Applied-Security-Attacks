import math
from attack import w,b,mask

# Helper function to initialise Montgomery variables
def mp_bits_per_limb(N):
    return mpz_size(N) * 4

def mpz_size(N):
    return Divide_Ceil(len("%X" % N), 16)

def mont_omega (N) :
    omega = 1
    for i in range(1, mp_bits_per_limb(N)):
        omega = (omega * omega * N) & (b - 1)
    return (b - omega)

def mont_r_sq (N) :
    r_sq = 1
    for i in range(2 * mp_bits_per_limb(N) * mpz_size(N)):
        r_sq = (r_sq + r_sq) % N
    return r_sq

def mpz_getlimbn(x, i):
    return (x >> w * i) & mask

# Montgomery multiplication
# r = a.b mod N
# Returns result and boolean to indicate whether a reduction was required
def mont_mul(x, y, N, omega):
    r = 0
    for i in range(0, int(mpz_size(N))):
        x0 = mpz_getlimbn(x, 0)             # 0-th limb a
        r0 = mpz_getlimbn(r, 0)             # 0-th limb r
        yi = mpz_getlimbn(y, i)             # i-th limb y
        u = (r0 + yi * x0) * omega % b      # u = (r0 + yi.x0).omega (mod b)
        r = (r + yi * x + u * N) / b        # r = (r + yi.x + u.N) / b
    if (r >= N) :
        return r - N, True
    else :
        return r, False

# Perform Montgomery Reduction
def mont_red(t, N, omega):
    for i in range(mpz_size(N)):
        ti = mpz_getlimbn(t, i)                        # get ith limb
        u  = ti * omega % b
        t  = t + u * (N << i * mp_bits_per_limb(N))     # t = t + u.N.(b ^ i)
    t >>= (mp_bits_per_limb(N) * mpz_size(N))          # t = t / b^size(N)
    if t > N:
        return t - N
    else:
        return t

# Left-to-right binary exponentiation, optimised with Montgomery Multiplication
# b ^ e (mod N)
def mont_L2R_exp(b, e, N, rho_2, omega):
    r = mont_red(rho_2, N, omega)
    bits_exp = int(math.log(e, 2))
    for i in range(bits_exp, -1, -1):           # For each bit in exponent
        r = mont_mul(r, r, N, omega)[0]         # r = r * r (mod N)
        if (e >> i) & 1:                        # if left most bit is 1
            r = mont_mul(r, b, N, omega)[0]     # r = r * b (mod N)
    return r

# Check if reduction is required for next bit (0 or 1) in private exponent
def next_bit_check(b, N, omega, r):
    r0, _      = mont_mul(r, r, N, omega)            # next bit
    _ , flag0  = mont_mul(r0, r0, N, omega)            # Check reduction if 0

    r1, _      = mont_mul(r0, b, N, omega)            # Check reduction if 1
    _ , flag1  = mont_mul(r1, r1, N, omega)
    return (flag0, flag1, r0, r1)


def Divide_Ceil(x, y):
    return -(-x // y)


# def Mont_Exp(b, x, y, N, omega):
#     rho_sq = Mont_Rho_Squared(b, N)
#     t_hat = Mont_Mul(b, 1, rho_sq, N, omega)[0]
#     x_hat = Mont_Mul(b, x, rho_sq, N, omega)[0]
#     y_bin = y
#
#     for i in range(0, len(y_bin)):
#
#         t_hat = Mont_Mul(b, t_hat, t_hat, N, omega)[0]
#
#         if (y_bin[i] == "1"):
#             t_hat = Mont_Mul(b, t_hat, x_hat, N, omega)[0]
#
#     t_hat = Mont_Mul(b, t_hat, t_hat, N, omega)[0]
#
#     t_temp = t_hat
#     # bit0
#     t_hat, flag = Mont_Mul(b, t_temp, t_temp, N, omega)
#
#     # bit1
#     t_hat = Mont_Mul(b, t_temp, x_hat, N, omega)[0]
#     t_hat, flag1 = Mont_Mul(b, t_hat, t_hat, N, omega)
#
#     return flag, flag1

# return Mont_Mul(b, t_hat, 1, N)#, flag
















#
#
#
#
#
# d = "1" #private key guess
# 	omega = Mont_Omega(b, N)
# 	mock_ciphers = gen_ciphers_list(10000)
#
# 	for c in mock_ciphers :
# 	   	( t, m ) = interact(c)
# 	   	add_timing( c, t)
# 	#print len(timings)
# 	print "Started loop: "
# 	for i in range(0, 64) :
# 	   	print ("Iteration",i)
# 	   	print ("key", d)
# 	   	#print("Init buckets")
# 	   	bucket1 = []
# 		bucket2 = []
# 		bucket3 = []
# 		bucket4 = []
# 	   	for c in mock_ciphers :
# 	   		#print c
# 	   		flagfor0, flagfor1 = Mont_Exp(2**64, c, d, N, omega)
# 	   		#print flagfor1, flagfor0
# 	   		if flagfor1:
# 	   			bucket1.append(timings[c])
# 	   			#print timings[c]
# 	   		else:
# 	   			bucket2.append(timings[c])
# 	   		if flagfor0:
# 	   			bucket3.append(timings[c])
# 	   		else:
# 	   			bucket4.append(timings[c])
# 	   	# print get_avg(bucket1)
# 	   	# print get_avg(bucket2)
# 	   	# print get_avg(bucket3)
# 	   	# print get_avg(bucket4)
#
# 		dif1 = abs(get_avg(bucket1) - get_avg(bucket2))
# 		dif2 = abs(get_avg(bucket3) - get_avg(bucket4))
# 		print (dif1, dif2)
# 	  	if(dif1 > dif2):
# 	  		d += "1"
# 	  	else:
# 	  		d += "0"
# 	  	print d





    # c_times, c_p, c_cur, test_cipher, test_message = generate_cs(N, d, r_sq, omega)
    #
    #
    # d = 1
    # print "Testing key bits"
    # for n in range( 0, w) :  # For each bit in private exponent d
    #     is0, not0, is1, not1, c0, c1 = [], [], [], [], [], []
    #     for i, c in enumerate(c_p):
    #         TEMP = c_cur[i]
    #         flag0, flag1, ci_0, ci_1 = next_bit_check(c,N,omega,TEMP)
    #         c0.append(ci_0)
    #         c1.append(ci_1)
    #
    #         if flag0 :
    #             is0.append(c_times[i])
    #         else :
    #             not0.append(c_times[i])
    #         if flag1 :
    #             is1.append(c_times[i])
    #         else :
    #             not1.append(c_times[i])
    #
    #     # Calculate the distinguisher
    #     diff0 = get_avg(is0) - get_avg(not0)
    #     diff1 = get_avg(is1) - get_avg(not1)
    #
    #     # Statistically guess a bit
    #     # If there is no difference, regenerate all messages and try this bit again
    #     if diff0 > diff1:
    #         d <<= 1
    #         c_cur = c0
    #     elif diff1 > diff0:
    #         d = (d << 1) + 1
    #         c_cur = c1
    #     else:
    #         print "Can't distinguish a bit"
    #         print "Bit 0: %d" % diff0
    #         print "Bit 1: %d" % diff1
    #         print "Regenerating Messages"
    #         c_times, c_p, c_cur, num_interactions, test_cipher, test_message = generate_cs(N, d, r_sq, omega)
    #
    #     print "Guessing bit %d, Key: %X" % (n, d)
    #     # Test if we have recovered the key by decrypting a ciphertext
    #     # This is done by bruteforcing the final bit, as we can't exploit
    #     # the square in the next round due to there not being another round
    #     if pow(test_cipher, d << 1, N) == test_message:
    #         d <<= 1
    #         break
    #     elif pow(test_cipher, (d << 1) + 1, N) == test_message:
    #         d = (d << 1) + 1
    #         break
    #
    # # Print results
    # print "Key Recovered"
    # print "Key: %X" % d
    # print "Message decrypted by key: %X" % pow(test_cipher, d, N)
    # print "Message decrypted by system: %X" % test_message



# # Generate test ciphertexts
# def generate_cs(N, d, r_sq, omega):
#     times , c_p, c_cur = [], [], []
#     print "Generating messages"
#     for i in range(13000):
#         c = random.randint(0, N)                        # Produce random Ciphertext between 0 <= c <= N
#         c_p.append(mont_mul(c, r_sq, N, omega)[0])      # Store c * r_sq mod N
#         c_cur.append(mont_L2R_exp(c_p[i], d, N, r_sq, omega)) # Calculate and Store
#
#         time, test_message = Interact(c)    # Interact using random Ciphertext
#         times.append(time)                 # Store time
#                              # Store
#
#     return times, c_p, c_cur, c, test_message