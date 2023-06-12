import random as random

# =============================================================================
#   CRYPTOGRAPHY PROBLEM SET 4
# =============================================================================

#Check the library struct
#Additional FUNCTIONS
def rot(aa,nn):
    aa = aa & 0xFFFFFFFF
    return ((aa >> nn) | (aa << (32 - nn))) & 0xFFFFFFFF

def RotateRight(w,n):
    '''w is an integer'''
    w = (32-w.bit_length())*'0' + bin(w)[2:]
    return int(w[-n%len(w):] + w[:-n%len(w)],2)

def ShiftRight(w,n):
    '''w is an integer'''
    if type(w) == str:
        w = int(w,2)
    return w >> n
          
#def barray(a,b):
#    tmp = bytes((b-1)) + bytes([a])
#    return tmp

def barray(a,b):
    tmp = []
    a = hex(a)[2:]
    for i in range(len(a),0,-2):
        if a[i-2:i] != '':
            tmp += [a[i-2:i]]
    if len(''.join(tmp)) != len(a):
        tmp.append(a[0])
    tmp.reverse()
    final = b''
    for i in tmp:
        final += bytes([int(i,16)])
    final = bytes(b-len(final)) + final
    return final  
    
def parse(a):
    W = ''
    for i in a:
        if len(hex(i))%2 != 0:              #In python, when transforming to hex it takes away the zeros on the left
            W += '0' + hex(i)[2:]
        else:
            W += hex(i)[2:]
    return int(W,0x10)


def S(x,a,b,c):
    return rot(x,a)^rot(x,b)^rot(x,c)

def s(x,a,b,c):
    return rot(x,a)^rot(x,b)^(x >> c)

def Maj(a,b,c):
    return (a & b) ^ (a & c) ^ (b & c)

def Ch(a,b,c):
    return (a & b)^(~a & c)


#PADDING ALGHORITHM

def pad(m,n):
    tmp = len(m)*8
    m += bytes([0x80])
    i = len(m)
    while i%n != n-8:
        m += bytes([0x00])
        i+=1
    m += barray(tmp,8)
    return m


#HASH ALGHORITHM
def hash256(M):
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,0x9b05688c,0x1f83d9ab, 0x5be0cd19]
    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8,0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138,0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1,0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,0xbef9a3f7, 0xc67178f2]
    M = pad(M, 64)
    i = 0
    tmp = [bytes(1) for x in range(8)]
    while i<len(M):
        W = []
        for j in range(16):
            W.append(parse(M[int(i/64)*64+j*4:int(i/64)*64+j*4+4]) & 0xFFFFFFFF)
        for j in range(16,64):
            W.append((W[j-16]+W[j-7]+s(W[j-15],7,18,3)+s(W[j-2],17,19,10)) & 0xFFFFFFFF)
        for j in range(8):
            tmp[j] = H[j]
        for j in range(64):
            t1 = (K[j]+W[j]+S(tmp[4],6,11,25) + Ch(tmp[4],tmp[5],tmp[6])+tmp[7]) & 0xFFFFFFFF
            t2 = (Maj(tmp[0],tmp[1],tmp[2]) + S(tmp[0],2,13,22)) & 0xFFFFFFFF
            for k in range(7,0,-1):
                tmp[k] = tmp[k-1]
            tmp[0] = (t1+t2) & 0xFFFFFFFF
            tmp[4] = (tmp[4] + t1) & 0xFFFFFFFF
        for j in range(8):
            H[j] = (H[j] + tmp[j]) & 0xFFFFFFFF
        i = i+64
    for i in range(len(H)):
        if len(hex(H[i]))%2 != 0:
            H[i] = '0' + hex(H[i])[2:]
        else:
            H[i] = hex(H[i])[2:]
    return ''.join(H)
    
# =============================================================================
#                   PROBLEM SET 4.1
# =============================================================================
    

def rot2(aa,nn):
    aa = aa & 0xFFFFFFFFFFFFFFFF
    return ((aa >> nn) | (aa << (64 - nn))) & 0xFFFFFFFFFFFFFFFF

def S2(x,a,b,c):
    return rot2(x,a)^rot2(x,b)^rot2(x,c)

def s2(x,a,b,c):
    return rot2(x,a)^rot2(x,b)^(x >> c)

def hash512(M):
    H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    K = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
         0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
         0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
         0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
         0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
         0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
         0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
         0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
         0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
         0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
         0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
         0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
         0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
         0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
         0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
         0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
         0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
         0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
         0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
         0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    M = pad(M,128)
    i = 0
    tmp = [bytes(1) for x in range(8)]
    while i<len(M):
        W = []
        for j in range(16):
            W.append(parse(M[int(i/128)*128+j*8:int(i/128)*128+j*8+8]) & 0xFFFFFFFFFFFFFFFF)
        for j in range(16,80):
            W.append((W[j-16]+W[j-7]+s2(W[j-15],1,8,7)+s2(W[j-2],19,61,6)) & 0xFFFFFFFFFFFFFFFF)
        for j in range(8):
            tmp[j] = H[j]
        for j in range(80):
            t1 = (K[j]+W[j]+S2(tmp[4],14,18,41) + Ch(tmp[4],tmp[5],tmp[6])+tmp[7]) & 0xFFFFFFFFFFFFFFFF
            t2 = (Maj(tmp[0],tmp[1],tmp[2]) + S2(tmp[0],28,34,39)) & 0xFFFFFFFFFFFFFFFF
            for k in range(7,0,-1):
                tmp[k] = tmp[k-1]
            tmp[0] = (t1+t2) & 0xFFFFFFFFFFFFFFFF
            tmp[4] = (tmp[4] + t1) & 0xFFFFFFFFFFFFFFFF
        for j in range(8):
            H[j] = (H[j] + tmp[j]) & 0xFFFFFFFFFFFFFFFF
        i = i+128
    for i in range(len(H)):
        if len(hex(H[i]))%2 != 0:
            H[i] = '0' + hex(H[i])[2:]
        else:
            H[i] = hex(H[i])[2:]
    return ''.join(H)
    



# =============================================================================
# =============================================================================
# =============================================================================
# =============================================================================
#                       TESTING THE CODE
# =============================================================================
# =============================================================================
# =============================================================================
# =============================================================================
def ascii2txt(A):                   #Convert from ASCII (str/binary integer) to text (str)
    A = str(A)
    if len(A)%8!=0:
        A = '0'*(8-len(A)%8)+A
    txt = ''
    for i in range(int(len(A)/8)):
        txt += chr(int(A[8*i:8*i+8],2))
    return txt


avail_chr = [chr(x) for x in list(range(33,127)) + list(range(161,256))]
def Testing_h256(ran):
    for i in range(ran):
        M = ''
        length = random.randint(1,500)
        for i in range(length):
            M += random.choice(avail_chr)
        Message = M.encode('utf-8')
        print('\nMessage:\n\n%s' % M,'\n\nAfter SHA - 256:\n%s' % hash256(Message))
        
def Testing_h512(ran):
    for i in range(ran):
        M = ''
        length = random.randint(1,1000)
        for i in range(length):
            M += random.choice(avail_chr)
        Message = M.encode('utf-8')
        print('\nMessage:\n\n%s' % M,'\n\nAfter SHA - 512:\n%s' % hash512(Message))

def Testing():
    print('============================================')
    print('================= SHA 256 ==================')
    print('============================================')
    Testing_h256(10)
    print('\n============================================')
    print('================= SHA 512 ==================')
    print('============================================')
    Testing_h512(10)
    print('\n\nNOTE:\nIn order to check everything, copy the text bellow "Message" without the last "space" and test on the website given by the professor')