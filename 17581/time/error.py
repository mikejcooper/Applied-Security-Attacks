from montgomery import mpz_size

'''
Error Class allows for attack certainty to be checked.
'''
class Errors:

    MARGIN = 0
    BITS = 0
    BitCertainty = []
    CipherithRound = []

    # Errors
    ErrorUncertain = False
    ErrorRevert = False
    ErrorResample = False
    ErrorIncreaseSample = False

    Resampled = False
    FailedDecryption = False

    RevertToBitX = 0
    ErrorCount = 0
    FailedDecryptionNum = 0


    # Go back to first unsure bit and resample or something else. Maybe don't try inverting bit

    def __init__(self, n):
        self.MARGIN = 4
        self.BITS=mpz_size(n) * 4
        self.BitCertainty=[True] * self.BITS
        self.CipherithRound = [[]] * self.BITS

    def Update(self, diffA, diffB, ithBit, c0, c1):
        self.UpdateBitCertainty(diffA, diffB, ithBit, c0, c1)

        if self.BitCertainty[ithBit] is False :
            self.ErrorUncertain = True
        else:
            self.ErrorUncertain = False

        if self.Revert(ithBit) and self.ErrorUncertain:
            self.ErrorRevert = True
        else :
            self.ErrorRevert = False

        if self.Resample() :
            self.ErrorResample = True
        else :
            self.ErrorResample = False

        if self.IncreaseSample() :
            self.ErrorIncreaseSample = True
        else :
            self.ErrorIncreaseSample = False

        if self.FailedDecryption and ithBit is 1:
            self.ErrorIncreaseSample = True
            self.ErrorResample = True
            self.FailedDecryption = False
        else:
            self.FailedDecryption = False



    def UpdateBitCertainty(self, diffA, diffB, ithBit, c0, c1):
        if self.differenceMargin(diffA, diffB):
            self.BitCertainty[ithBit] = True
        elif self.differenceMargin(diffB, diffA):
            self.BitCertainty[ithBit] = True
        else:
            self.ErrorCount += 1
            # Difference not high enough. Highlight uncertainty at index i and store ciphertexts
            if diffA > diffB :
                self.BitCertainty[ithBit] = False
                self.CipherithRound[ithBit] = c0
            else :
                self.BitCertainty[ithBit] = False
                self.CipherithRound[ithBit] = c1

    # If there are two uncertain bits that follow an uncertain bit
    def Revert(self, ithBit):
        uncertain_bits = []
        for i in range(ithBit, ithBit - 10, -1):
            if i < 0 :
                break
            if self.BitCertainty[i] is False :
                uncertain_bits.append(i)
            if len(uncertain_bits) > 3:
                for bit in uncertain_bits :
                    self.BitCertainty[bit] = True
                self.RevertToBitX = uncertain_bits[-1]
                return True
        return False

    def Resample(self):
        if self.ErrorCount > 6:
            self.ErrorCount = 0
            self.Resampled = True
            self.ResetBitCertainty()
            return True
        else :
            return False

    def IncreaseSample(self):
        if self.ErrorResample and self.Resampled :
            self.ResetBitCertainty()
            return True
        else :
            return False

    def differenceMargin(self, diffA, diffB):
        if diffA - diffB > self.MARGIN:
            return True
        else:
            return False

    def ResetBitCertainty(self):
        for i in range(0, len(self.BitCertainty)):
            self.BitCertainty[i] = True