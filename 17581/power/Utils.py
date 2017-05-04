import hashlib
import binascii
import math

import numpy
from Crypto.Cipher import AES
import pickle


# Inverse S-box
inv_s = \
    [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    ]

def AES_check( m, c, k ) :
    c1 = AES.new( HexToByte(k) ).encrypt( HexToByte(m) )
    if HexToByte(c) == HexToByte(c1):
        return True
    else :
        return False

def AES_1_Block(text):
    return hashlib.md5(text).digest()

def AES_2_Block(text):
    return hashlib.sha256(text).digest()

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

# Convert hex to Byte List
def HexToByteList(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string) - 1, 2)]

# Convert hex to Byte List
def ByteListToHexString(byteList):
    return "".join([("%X" % byte).zfill(2) for byte in byteList])

# Convert Byte (4 bit) string to Hex (2 bit) string
def ByteToHex(byte_string) :
    if len(byte_string) <= 16:
        return binascii.hexlify(byte_string).zfill(32)
    else :
        return byte_string.zfill(32)

# Convert Byte (4 bit) string to Hex (2 bit) string
def ByteToHex256(byte_string):
    if len(byte_string) <= 32:
        return binascii.hexlify(byte_string).zfill(64)
    else:
        return byte_string.zfill(64)

# Convert Hex (2 bit) string to Hex (4 bit) string
def HexToByte(hex_string) :
    if len(hex_string) <= 16:
        return hex_string.zfill(16)
    else :
        return hex_string.strip().zfill(16).decode('hex').zfill(16)

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
        return X.zfill(32)
    else:
        return format(X, 'X').zfill(32)


# Convert to Hex string
def toHex(X):
    if isinstance(X, ( int, long )):
        return "%X\n" % X
    elif X == '':
        return 0
    else:
        return X.encode('hex')

# Multiply a(x) by x
def gf28_mulx(a):
    return (((a << 1) ^ 0x1B) if a & 0x80 else (a << 1)) & 0xFF

# Multiply a(x) by b(x)
def gf28_mul(a, b):
    t = 0
    for i in range(7, -1, -1):
        t = gf28_mulx(t)
        if (b >> i) & 1:
            t ^= a
    return t



# Utils for ATTACK


def getTrace(_traces) :
    __traces = _traces.split(',')[1:]
    traces = []
    for i in __traces:
        traces.append(int(i))
    return (traces)

def preprocessTrace(_traces):
    avg = numpy.mean(_traces)
    std = numpy.std(_traces)
    x = std
    traces = []
    for i in _traces:
        if i > x + avg or i < avg - x:
            traces.append(int(i))
    return traces

def sameLengthTraceSets(traces):
    smallest = len(traces[0])
    for t in traces:
        if len(t) < smallest:
            smallest = len(t)
    for i in range(len(traces)):
        tmp = traces[i]
        traces[i] = tmp[:smallest]
    return traces


def printComparison(newByte, i, key):
    if key == 1:
        str1 = "1BEE5A32595F3F3EA365A590028B7017"
    else:
        str1 = "5B6BA73EB81D4840B21AE1DB10F61B8C"
    ind = i * 2
    str_i = str1[ind:ind + 2]

    scale = 16  ## equals to hexadecimal
    num_of_bits = 8
    print "True:  Byte " + str(i) + " : " + bin(int(str_i, scale))[2:].zfill(num_of_bits) + " : " + str_i
    print "Guess: Byte " + str(i) + " : " + bin(int(newByte, scale))[2:].zfill(num_of_bits) + " : " + newByte


def getByte(ciphertext, index) :
    return int(ciphertext[index*2 : index*2 + 2], 16)


def storeInfo(info):
    afile = open(r'C:\d.pkl', 'wb')
    pickle.dump(info, afile)
    afile.close()

def storeInfo1(info):
    afile = open(r'C:\d1.pkl', 'wb')
    pickle.dump(info, afile)
    afile.close()

def getInfo():
    # reload object from file
    file2 = open(r'C:\d.pkl', 'rb')
    new_d = pickle.load(file2)
    file2.close()
    # print dictionary object loaded from file
    return new_d

def getInfo1():
    # reload object from file
    file2 = open(r'C:\d1.pkl', 'rb')
    new_d = pickle.load(file2)
    file2.close()
    # print dictionary object loaded from file
    return new_d

def check(key1, key2, i, j, c):
    key1 = HexToByte(key1)
    key2 = HexToByte(key2)
    _i = HexToByte(i)
    c = os2ip(c)

    # Checks
    os = "1BEE5A32595F3F3EA365A590028B7017"
    os2ip1 = os2ip(os)
    i2osp1 = i2osp(os2ip1).upper()

    hex = "1BEE5A32595F3F3EA365A590028B7017"
    h1 = HexToByte(hex)
    b1 = ByteToHex(h1).upper()

    aes1 = AES.new(key1).encrypt(_i)
    aes2 = AES.new(key1).decrypt(aes1)
    aes2 = ByteToHex(aes2).upper()

    if(hex == b1):
        print "Hex2Byte works"
    if(os == i2osp1):
        print "i2os works"
    if (aes2 == i):
        print "AES works"



    T = AES.new(key2).encrypt(_i)
    T = os2ip(ByteToHex(T))
    # Next operation: Group multiplication with j, but j = 0. Therefore T stays the same.
    CC = c ^ T
    PP = AES.new(key1).decrypt(HexToByte(i2osp( CC )))
    PP = os2ip(ByteToHex(PP))
    P = PP ^ T
    return i2osp(P)


CIPHERTEXTS = [
'9F3102033F3189E703241DDD4EFAE424',
'BC65BD854FFA22EEE7968119C2083DAB',
'D944E25E3DA2D91E3D0DC64C291C38AF',
'50BC72C6453E51B23548918F01AAD0BE',
'0D831A049D3B107FD716090674863B03',
'315BA7526134B5535EF38FD1221E6E75',
'69D1823C4FFA0DAC35B8CA32D8CB7CFD',
'F1DA5B81CACA19494E6986A4708A768A',
'AE2433852296ECAC0F623B2F14B5A141',
'7FC2183C22FF635CB089090AC6D5A33D',
'66F66FF43A0C4E78D1B8DF50F938C743',
'9FC9395BF63D4A7D26F6E8ADA15A19F7',
'97B175C306A3307D59BE008D3D208681',
'747025095E80DE639AAB835253BF905F',
'074B3B79D8E8253108463F257D502B77',
'A44D1F3D9AA5EAC34E679DB3A82607E0',
'5A2C4512A2E89CBFCF4F46CF4F0C20F9',
'878823BBC896DC707ACBE098A994EC9D',
'3B1A216FAB0CE1BF353DD5224DA2553D',
'FD75C5358667743A64170522ADD156A8',
'2292893A6B6D5177D9643DF158BB4E6C',
'3EBEC7662B60486F0D69DAEBA17ADF85',
'31A592DA9A32F1B042738F8838EBA04D',
'D29CCD7BF7BD8578156AC82E852CAC81',
'6BF62DC14B97401A90A8D128A2B2AF66',
'9178C1D512D941C9BD7B0D32C8D6E0A1',
'B2BFDE18E5B19D3B2AC7C2EE382AC2E0',
'945566AEF2CD09012553F7F85FEBC2A9',
'7826DC7BC0FFC200AD6744D99441B2F5',
'C13D0F65F40ECECF6290279499F412AF',
'ED9426F44F5FB4CCC115632AEEB0269E',
'E014F1FE3C8159E06A4AB62FF8646655',
'79CF7C6D740F7B1873C234F9D0AF12D4',
'8276E1063DEF104D7D0021253EA7A9C8',
'E85E8E80EC1CE61D140007C0133D786B',
'F381C81F51B8B80B23840BB5D4C8EF80',
'BBE9409C02FA7E5640ACF8B093D8618E',
'8619F920E224090E2E770A3F72713321',
'3D6634591EF39DD5FB2EB9666B2C9C8D',
'2F81B63188F57495EEE8C18580946168',
'FBFED01A8C1DFC5068A2019102E6C3BF',
'AEB8835F3C0E49C77D50D556AE14AD9D',
'0854243D19387736F4F9020D797B0C46',
'18A896369FA6D2298848406B0E4B7A68',
'B68BD704831E6A03BAA0670B207FB543',
'3B0B2779ACD22E6642646A8D3E83C5C5',
'D0C0D53D80533E6F72B96515B945973C',
'5242CD69AC1081ABE1F55F0669782306',
'0F96D2ABAE55F4BE5D754B78C350172A',
'6EF2DA719D1D6DB8B9ACDBD3420EADED',
'93478B98CA190BF89B681D933FE05494',
'0E2840FEEBBAC7CFCED0DEDAF8EB140D',
'3C18DE1BE7439182E98C5418E972831B',
'D696922F2F1D0A9AEB8BCD84D6E39692',
'A6C451DAE701F3B65FD011AE088AA2F9',
'5FAC4E91FA09B4FB867602B753E9F0A9',
'E4D4476766791A50A27E8E3E800B9C76',
'BFD89E3787FF71406708F1A3D6494A31',
'9CBE42451E6141366FDC196DBE5DEC83',
'9AFAE2E3DF1AA85A6066975F1E2B720E',
'CD7F6381F9A1AE3BFC6384FFA30B6F19',
'B337F93823FE35BC44F7AD9A2E78698D',
'83856BB3DF0D83436739C90BB7594763',
'616A5CAF814D4B15AF4E8182B35D4046',
'8D5B6737BCFE36704D5950929E65AF52',
'A3B7393E6891CEB820C61FFF05B40A48',
'70C4786D4E77FA0CC3D5E1353C6DE85A',
'89CF087FF02CEE12C7FE4C717277829A',
'6AF846466A9ACE94FA310D8A68BFB3D5',
'272DF42802354401A81FEB5ACEFA751B',
'5689B2AE284C63AF9D6F0DE40258842B',
'85C5DBBFAC3D6E98AF184A4C4061E6CC',
'829EA6E1CCD815759E7A2FE7B27CDDBD',
'35BBDCBF2FD4DEAD50A75AC35B4F28B8',
'51CC04B273E0450D837DD1CE212063C3',
'378E883891FA00C5E92709752E532E41',
'FC83122D660C5ADC6D1F4429F0910F5C',
'53FF8EFF757DBEAF8F8C8F7436A2C073',
'43762E0C96AB276DBC65226D9E69F903',
'16AA17B90E954012745251B99DFCBCA1',
'5F273F1846333410DE9BBEAE2B3A328D',
'99D56B6356676D741A5EA7A7C678DD02',
'AD8F2FDD9B39AE06D3F9D360D4963F27',
'238A0A1B1CC870EFA0E9CB5F3CAA3CDB',
'BF9F72B2AFA954AAEA588720B1AF1695',
'9231B986958D7EA68A3F6F45D6E52846',
'73C2243D5DDD7BEA3723A60E18B32C15',
'DDC17895187EED30F75206DA18B04964',
'16CE317D61BDA7D13115F85832C14F7C',
'9CB9333DF2048B96ECC2AE2318359473',
'5D6EA3D34714248E132FB5EE7B2ED801',
'3EC35BA8A40E6CFC774F38E632CB28E3',
'77CACA6762A36427DAFD5F0A51E3CA67',
'BAA271694379B0C068F0DA403ABBB814',
'F0ECBE0120C6B624790FA136D1ACB8F8',
'9F377A185F3D059AFCA37D018D1FE179',
'10BA29338BF297B00522A2DC460C5B09',
'025AA6F26C6E6006976412C7197978E3',
'76E658958CE8C5B0F9E7E95395B0FA41',
'77EAED7607007A7667C8C57B5C0AB338',
'14A76777D8F28F866F6E71BB6807FA34',
'94A59BFFDCDCC7E3F8AEB332B96CAB48',
'81A3EF1A9838181996B59507218DDA9B',
'3C8D3A89A51BC0A034760439F721160C',
'9493469C6905E6E62FFA6929D2D26D11',
'826E225A0533782DDA22D7B1A52DD07F',
'4C2821483F3B212E4680FA9981945916',
'7EA484CAC83EE30BF06DA21FEB08D734',
'2BCF94382CC66E45969D20138486B6CE',
'8972B2C5C9A5602D92926AA44D04D598',
'D4E672747EDF034695408F94B0C63FC4',
'DC43EB7F7FD3F6D47B47CE900CCF325D',
'F66A46A78F513148B94B7FF99B83C3CB',
'04C1D605E0BFFD313D9AD1A72420DA7F',
'BB6679B5956BBA97B618CB12150990B4',
'1BEE5A32595F3F3EA365A590028B7017',
'5B6BA73EB81D4840B21AE1DB10F61B8C',
'7307464080FA6B73C4049511CB2CB83E',
'79266DB0CD810123352F6D7707B20574',
'A99CE4A0687CE8E8D1140F2EC21345EB',
'CE8E9260363AF9CDAD3ABFBC6C597624',
'1408458C6BFA2ED8EEB72E132C6A077F',
'2A4220F16F55845CDE1B809800BA6A20',
'E955A474B77E5BE7CDC8EAC0D3B8E58C',
'7B99BD13CBE6B4EED22B48F58151FCF8',
'9A43B540C55937667BE369B714A438CD',
'03B7EF046CB22798037DCF44AEEBECC1',
'8E97485CD6DD82A4A51EA0432EE6FB72',
'6B5EC57253F3E1B45E4E087971865AF1',
'A129DD64819E43C32410597209F2CDD1',
'3D48F9F6BF0A9FC12B39690CC4FEF94E',
'C2124D82CE04B0697D5EDA88DDDD5902',
'AE3BC360D1E468257D210AA424E883D6',
'CC694612AF813B6269E9CD630442C286',
'86CC67106EFD94C39B3239EBAF77F9D5',
'C43B622A67106F24281398E333A82D3F',
'4896373A334B576965F8AD8DB4439F48',
'95C7D4E4969B5C3A5E01C3DC4B5A49D5',
'94E72FCA235B063B62D5C95D05236679',
'4BB880C919BCCDAA23D759C3526562A6',
'7D1BB8D4A1CC40435D11710870C439AC',
'4E8CFC4C2C76A64516CB791361189DA0',
'916183031259C133FDD4F01DBC006EFC',
'49AF9DF63685212745AB46A1CE99681B',
'17C19C6791EC8B220DB31411D329AD61',
'CE0F19AAFFFC8C5484A6B4691D1AF6AB',
'B1B119322FADD2248115A2995565D185',
'286AEFFE05F36D8C2601A1F2E99FF430',
'7BF67375A96E99C944AE0E7A3648A23E',
'1B5AC198C861B631D32FD258BA4A0579'
]
