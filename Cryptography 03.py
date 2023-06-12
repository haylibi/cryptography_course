#import numpy as np
import random
import Crypto.Util.number as cu
import hashlib as hl

#Auxiliary functions
def txt2ascii(Text):                #Convert a text (str or bytes) to ASCII (str)
    text_binary = []
    if type(Text) != bytes:
        Text = bytes(Text,'utf-8')
    for i in range(len(Text)):                                      
        binary = bin(Text[i])[2:]
        if len(binary)<8:
            text_binary.append((8-len(binary))*'0'+binary)
        else:
            text_binary.append(binary)
    return ''.join(text_binary)

def ascii2txt(A):                   #Convert from ASCII (str/binary integer) to text (str)
    A = str(A)
    if len(A)%8!=0:
        A = '0'*(8-len(A)%8)+A
    txt = b''
    for i in range(int(len(A)/8)):
        txt += bytes([int(A[8*i:8*i+8],2)])
    return txt


def bin2decimal(n):                 #Convert binary (int/str) to decimal (integer) 
    number = 0
    n = str(n)
    for i in range(1,len(n)+1):
        if n[-i] == '1':
            number += pow(2,i-1)
    return number

def bitlen(k):
    return len(bin(k)[2:])

def phi(p,q):                   #Totient function if p and q are prime
    '''p and q prime'''
    return (p-1)*(q-1)


# =============================================================================
#                               CHAPTER 3.1
# =============================================================================
    

# =============================================================================
# Exercise 2 from 3.1
# =============================================================================
#RSA
def RSA_keygen():
    p = cu.getPrime(int(1024-128/2))
    q = cu.getPrime(int(1024+128/2))
    n = p*q
    phii = phi(p,q)
    while True:
        e = random.randint(pow(2,(1/4*bitlen(phii))),phii)
        if cu.GCD(e,phii) == 1:
            break    
    d = cu.inverse(e,phii)
    return (n,d,e)


def RSA_Cypher(Message,n,e):            #Cyphers a message using RSA 
    '''Message is a byte array'''
    M = txt2ascii(Message)
    M = bin2decimal(M)
    C = pow(M,e,n)
    return C        #Returns all the numbers and the cyphered message (as a number)

def RSA_Decypher(C,n,d):
    M = pow(C,d,n)
    M = bin(M)[2:]
    message = ascii2txt(M)
    return message


#Mask generating function
# =============================================================================
# Exercise 3 from 3.1
# =============================================================================
def i2osp(integer, size = 4):                               #Function that returns a number in byte representation of 4 bytes
    return b''.join([bytes([((integer >> (8 * i)) & 0xFF)]) for i in reversed(range(size))])

def mgf1(message, length, hash = hl.sha256):     
    '''message is a byte array'''
    if type(message)!= bytes:
        m = bytes(message,'utf-8')
    else:
        m = message
    hLen = len(hash(b'').digest())
    output = b''
    for i in range(length // hLen + 1):
        temp = hash(m + i2osp(i)).digest()
        output += temp
    return output[:length]

# =============================================================================
#                           Chapter 3.2
# =============================================================================

# =============================================================================
# Exercise 1 
# =============================================================================
def Chapter32ex1():
    (n,d,e) = RSA_keygen()
    c1 = RSA_Cypher(chr(2), n, e)
    c2 = RSA_Cypher(chr(12), n, e)
    print(ord(RSA_Decypher(c1*c2, n, d).decode('utf-8')))


#OAEP
    
def bxor(b1, b2):                   #xor for bytes
    output = []
    for (a, b) in zip(b1, b2):
        output.append(bytes([a ^ b]))
    return b''.join(output)

# =============================================================================
# Exercise 2
# =============================================================================

#ENCODING
def OAEP_Encoding(M, H = hl.sha256):
    '''M must be bytes type'''
    if type(M) != bytes:
        raise ValueError('Message must be of type "bytes"')
    hlen = len(H(b'').digest())
    K = 255
    mLen = len(M)
    if mLen > K - 2*hlen - 2 - 1:      #the "-1" on the end is to ensure len(PS) > 0
        raise ValueError
    lhash = H(b'').digest()
    PS = (K - len(M) - 2*hlen - 2)*b'\x00'
    DB = lhash + PS + b'\x01' + M
    seed = b''.join([bytes([random.randint(0,255)]) for i in range(hlen)])
    dbMask = mgf1(seed, K - hlen - 1)
    maskedDB = bxor(DB, dbMask)
    seedMask = mgf1(maskedDB, hlen)
    maskedSeed = bxor(seed, seedMask)
    EM = b'\x00' + maskedSeed + maskedDB
    return EM

#DECODING
def OAEP_Decoding(EM, H = hl.sha256):
    hlen = len(H(b'').digest())
    k = len(EM)
    (Y, maskedSeed, maskedDB) = (EM[0],EM[1:hlen+1],EM[hlen+1:])    
    lhash = H(b'').digest()    
    seedMask = mgf1(maskedDB, hlen)    
    seed = bxor(maskedSeed, seedMask)    
    dbMask = mgf1(seed, k - hlen - 1)    
    DB = bxor(maskedDB, dbMask)
    lhash2 = DB[:hlen]    
    i = hlen + 1
    while True:
        if DB[i] != b'\x00'[0]:
            break
        i+=1
    if DB[i] != b'\x01'[0]:
        raise ValueError('Error')
    M = DB[i+1:]
    if lhash2 != lhash:
        raise ValueError('Hash arent the same')
    if Y != 0:
        raise ValueError('Your input wasnt valid for the first value (it should be 0)')
    return M                    #M IS NOT DECODED, IT'S STILL IN BYTE


# =============================================================================
# Exercise 3
# =============================================================================
#RSA IMPROVED
def bin2byte(M):
    byt = b''
    while M != '':
        byt += bytes([int(M[:8],2)])
        M = M[8:]
    return byt

def byte2bin(M):
    bi = ''
    for i in M:
        temp = bin(i)[2:]
        if len(temp) != 8:
            temp = '0'*(8-len(temp)) + temp
        bi += temp
    return bi

def RSA_OAEP_Encoding(Message,n,e):            #Cyphers a message using RSA
    if type(Message) != bytes:
        Message = Message.encode('utf-8')
    EM = OAEP_Encoding(Message)
    asci = byte2bin(EM)
    M = int(asci,2)
    C = pow(M,e,n)
    return C

def RSA_OAEP_Decoding(C,n,d):
    M = pow(C,d,n)
    bi = bin(M)[2:]
    if len(bi)%8 != 0:
        bi = '0'*(8-len(bi)%8)+bi
        bi = 8*'0' + bi
    if len(bi)/8 < 255*8:
        bi = '0'*(255*8-len(bi)) + bi
    EM = bin2byte(bi)
    Message = OAEP_Decoding(EM)
    return Message


# =============================================================================
#                           CHAPTER 3.3
# =============================================================================

# =============================================================================
# Exercise 1
# =============================================================================
#RSA - KEM SENDER
def RSA_KEM_SENDER(n,e,hash = hl.sha256):                    
    '''n and e are numbers generated from RSA_keygen() and n shoud be 255 bytes long'''
    RAND = random.randint(2,2**187)
    bi = bin(RAND)[2:]
    if len(bi)%8!=0:
        bi = '0'*(8-len(bi)%8) + bi
    BRAND = bin2byte(bi)
    BKEY = hash(BRAND).digest()
    BC = RSA_OAEP_Encoding(BRAND,n,e)
    return BC,BKEY

#RSA - KEM RECEIVER
def RSA_KEM_RECEIVER(BC,n,d, hash = hl.sha256):
    '''n and d are the numbers generated from RSA_keygen() used in RSA_KEM_Sender'''
    KEY = RSA_OAEP_Decoding(BC,n,d)
    BKEY = hash(KEY).digest()
    return BKEY



# =============================================================================
# Exercise 2
# =============================================================================
#EMSA - PSS
def EMSA_Encode(M, emLen = 255, Hash = hl.sha256):
    '''M is a message in bytes'''
    if type(M)!= bytes:
        raise ValueError('Please insert M as a byte sequence')
    hLen = len(Hash(b'').digest())
    sLen = len(Hash(b'').digest())
    if emLen < hLen + sLen + 2:
        raise ValueError('Message length in bytes should be greater then', hLen + sLen + 2)
    mHash = Hash(M).digest()
    salt = b''.join([bytes([random.randint(0,255)]) for i in range(sLen)])
    M2 = bytes(8) + mHash + salt
    H = Hash(M2).digest()
    PS = bytes(emLen - sLen - hLen - 2)
    DB = PS + bytes([1]) + salt
    dbMask = mgf1(H, emLen - hLen - 1)
    maskedDB = bxor(DB, dbMask)
    EM = maskedDB + H + bytes([0xbc])
    return EM


#EMSA Verification
def EMSA_Verify(M,EM, Hash = hl.sha256):
    hLen = len(Hash(b'').digest())
    sLen = hLen
    emLen = len(EM)
    if emLen < hLen + sLen + 2:
        print('Signature Invalid 1')
        return False
    mHash = Hash(M).digest()
    if EM[-1] != 0xbc:
        print('Signature Invalid 2')
        return False
    (maskedDB, H) = (EM[:emLen - hLen - 1], EM[emLen - hLen - 1:emLen - 1])
    dbMask = mgf1(H, emLen - hLen -1)
    DB = bxor(maskedDB, dbMask)
    if DB[:emLen -hLen - sLen - 2] != bytes(emLen-hLen-sLen-2):
        print('Signature Invalid 3')
        return False
    if DB[emLen - hLen - sLen - 2] != 1:
        print('Signature Invalid 4')
        return False
    salt = DB[-sLen:]
    M2 = bytes(8) + mHash + salt
    H2 = Hash(M2).digest()
    if H2 != H:
        print('Signature Invalid 5')
        return False
    else:
        return True
    
    
    
# =============================================================================
# Exercise 3
# =============================================================================
#RSA - PSS
        
#RSA - PSS Creation for a message M
(a,b,c) = RSA_keygen()
def RSA_PSS_Creation(Message,n = a,d = b):      #if no numbers are specified, the creation will use the (a,b,c) values generated
    '''Message should be in bytes'''
    if type(Message) != bytes:
        raise ValueError("Message isn't expressed in bytes")
    BEM = EMSA_Encode(Message)
    EM = int(byte2bin(BEM),2)
    EM = pow(EM,d,n)
    EM_bin = bin(EM)[2:]
    if len(EM_bin)%8 != 0:
        EM_bin = '0'*(8-len(EM_bin)%8)+EM_bin
    SIG = bin2byte(EM_bin)
    return (SIG)


#RSA - PSS Verification for a message M and a signature SIG
def RSA_PSS_Verify(Message,SIG,n = a,e = c):
    EM = int(byte2bin(SIG),2)
    EM = pow(EM,e,n)
    EM_bin = bin(EM)[2:]
    if len(EM_bin)%8 != 2040:
        EM_bin = '0'*(2040-len(EM_bin))+EM_bin
    BEM = bin2byte(EM_bin)
    return EMSA_Verify(Message, BEM)



# =============================================================================
# =============================================================================
# =============================================================================
# =============================================================================
#                           TESTING THE CODE
# =============================================================================
# =============================================================================
# =============================================================================
# =============================================================================




#RSA TESTING
def Testing_RSA(ran):
    for i in range(ran):
        if i==0:
            print('RSA TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            

        (n,d,e) = RSA_keygen()                          #Generating a different RSA key
        M = bin(random.randint(2,2**180))[2:]           #Generating a random message in bytes
        if len(M)%8!=0:
            M = '0'*(8-len(M)%8) + M
        M = ascii2txt(M)
        C = RSA_Cypher(M,n,e)
        if M != RSA_Decypher(C,n,d):
            raise ValueError('Fail RSA')
    print('100% \nCompleted with no error!')

#MASK GENERATING FUNCTION
def Testing_MGF1(ran):
    for i in range(ran):
        if i==0:
            print('MGF TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            
        M = bin(random.randint(2,2**180))[2:]           #Generating a random message in bytes
        if len(M)%8!=0:
            M = '0'*(8-len(M)%8) + M
        M = ascii2txt(M)
        length = random.randint(1,255)
        mgf = mgf1(M,length)
        if len(mgf) != length:
            raise ValueError('Fail MGF')
    print('100% \nCompleted with no error!')



#OAEP TESTING
def Testing_OAEP(ran):
    for i in range(ran):
        if i==0:
            print('OAEP TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            
            
        M = bin(random.randint(2,2**180))[2:]           #GENERATING A RANDOM MESSAGE IN BYTES
        if len(M)%8!=0:
            M = '0'*(8-len(M)%8) + M
        M = ascii2txt(M)
        
        
        EM = OAEP_Encoding(M)
        if OAEP_Decoding(EM) != M:
            raise ValueError('Fail OAEP')
    print('100% \nCompleted with no error!')


#RSA With OAEP testing
def Testing_RSA_OAEP(ran):
    (n,d,e) = RSA_keygen()                          
    for i in range(ran):
        if i==0:
            print('RSA OAEP TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
        
        
        M = bin(random.randint(2,2**180))[2:]           #GENERATING A RANDOM MESSAGE IN BYTES
        if len(M)%8!=0:
            M = '0'*(8-len(M)%8) + M
        M = ascii2txt(M)
        
        C = RSA_OAEP_Encoding(M,n,e)
        if M != RSA_OAEP_Decoding(C,n,d):
            raise ValueError('Fail RSA_OAEP')
    print('100% \nCompleted with no error!')



#RSA - KEM TESTING
def Testing_RSA_KEM(ran):
    (n,d,e) = RSA_keygen()
    for i in range(ran):
        if i==0:
            print('RSA - KEM TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            
            
        (BC,BKEY) = RSA_KEM_SENDER(n, e)
        if BKEY != RSA_KEM_RECEIVER(BC, n, d):
            raise ValueError('Fail RSA_KEM')
    print('100% \nCompleted with no error!')



#EMSA TESTING
def Testing_EMSA(ran):
    for i in range(ran):
        if i==0:
            print('EMSA TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            
            
        M = bin(random.randint(2,2**180))[2:]           #GENERATING A RANDOM MESSAGE IN BYTES
        if len(M)%8!=0:
            M = '0'*(8-len(M)%8) + M
        M = ascii2txt(M)
        EM = EMSA_Encode(M)
        if EMSA_Verify(M,EM) == False:
            raise ValueError('Fail EMSA')
    print('100% \nCompleted with no error!')
    
#RSA - PSS
def Testing_RSA_PSS(ran):
    (n,d,e) = RSA_keygen()
    for i in range(ran):
        if i==0:
            print('EMSA TESTING PERCENTAGE')
        elif (i/ran*100)%10 == 0.0:
            print('%d%s' % (i*100/ran,'%'))
            
            
        M = bin(random.randint(2,2**180))[2:]           #GENERATING A RANDOM MESSAGE IN BYTES
        if len(M)%8!=0:
            M = M[:len(M) - len(M)%8]
        M = ascii2txt(M)
        SIG = RSA_PSS_Creation(M, n, d)
        if RSA_PSS_Verify(M,SIG,n,e) != True:
            raise ValueError('Fail RSA PSS')
    print('100% \nCompleted with no error!')


def Testing():
    Testing_RSA(100)
    Testing_MGF1(10000)
    Testing_OAEP(10000)
    Testing_RSA_OAEP(100)
    Testing_RSA_KEM(100)
    Testing_EMSA(100)
    Testing_RSA_PSS(100)