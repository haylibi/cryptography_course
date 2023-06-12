import numpy 
import sympy
#import pycrypto
import random
def length(n):
    return len(str(numpy.binary_repr(n)))

def txt2ascii(Text):                #Convert a text (str) to ASCII (str)
    text_binary = []
    for i in range(len(Text)):                                      
        binary = bin(ord(Text[i]))[2:]
        if len(binary)<8:
            text_binary.append((8-len(binary))*'0'+binary)
        else:
            text_binary.append(binary)
    return ''.join(text_binary)

def ascii2txt(A):                   #Convert from ASCII (str/binary integer) to text (str)
    A = str(A)
    if len(A)%8!=0:
        A = '0'*(8-len(A)%8)+A
    txt = ''
    for i in range(int(len(A)/8)):
        txt += chr(int(A[8*i:8*i+8],2))
    return txt

#Exercise 1
def Ex1():
    a = 4
    b = 14
    a = a^b
    b = a^b
    a = a^b
    print('Exercise 1:\na =',a,'b =',b,'\n')


#Exercise 2
def Ex2():
    p = random.randint(2**127,2**128-1)
    q = random.randint(2**63,2**64-1)
    n = p*q
    print('Exercise 2: \nlen(n) =',length(n),'\n')

#Exercise 3
def Ex3():  
    p = 0
    q = 0
    while True:                                         # Generating pseudo-random key (p and q with 512 bits)
        prime = random.getrandbits(512)
        if prime%4 == 3:
            if sympy.ntheory.primetest.isprime(prime):
                if p == 0:
                    p = prime
                if q == 0 and prime != p:
                    q = prime
                    break
    return (p,q)


#Exercise 4
def Ex4(Text):
    '''Text is the message to be cyphered (string form)'''
    (p,q) = Ex3()
    n = p*q
    while True:                                                 #Generating pseudo-random key (s)
        s = random.randint(1,n-1)
        if numpy.gcd(s,n)==1 and 4*len(str(numpy.binary_repr(s)))>1024:
            break
    text_binary = txt2ascii(Text)
    text_bit = len(text_binary)
    x0=s**2%n
    xt=x0**2%n
    kt=[]
    for i in range(text_bit):                               #Generating as many 1's and 0's as needed for the respective message
        xt = xt**2%n
        kt.append(str(xt%2))
    kt = ''.join(kt)
    #Xor C = M ^ K
    C = int(text_binary,2) ^ int(kt,2)
    print("key =",kt)
    cyphered = ascii2txt(bin(C)[2:])
    print('Cipher text:',cyphered)
    #Xor M = C ^ K
    M = C ^ int(kt,2)
    Decypher = ascii2txt(bin(M)[2:])
    print('Original message:',Decypher)
    
    