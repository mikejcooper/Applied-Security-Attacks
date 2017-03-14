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

    def Revert(self, ithBit):
        for i in range(ithBit - 4, ithBit-1):
            if self.BitCertainty[i] is False :
                self.BitCertainty[i] = True
                self.RevertToBitX = i
                return True
        return False

    def Resample(self):
        if self.ErrorCount > 4:
            self.ErrorCount = 0
            self.Resampled = True
            return True
        else :
            return False

    def IncreaseSample(self):
        if self.ErrorResample and self.Resampled :
            return True
        else :
            return False

    def differenceMargin(self, diffA, diffB):
        if diffA - diffB > self.MARGIN:
            return True
        else:
            return False