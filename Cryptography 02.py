import numpy 
import sympy

#Function greatest common divisor
# =============================================================================
#   EXERCISE 1
# =============================================================================
def GCD(a,b):
    if a<b:
        (a,b) = (b,a)
    while a%b!=0:
        (a,b) = (b,a%b)
    return b
def Ex1():
    print('GCD(59, 22) =',GCD(59, 22), 
          '\nGCD(15, 7) =',GCD(15, 7), 
          '\nGCD(101, 49) =',GCD(101, 49),
          '\nGCD(123, 66) =',GCD(123, 66))
#Inverse modulate operation (find x such as xa = 1 (mod b), 0<x<b)

def phi(x):
    count = 0
    for i in range(1,x+1):
        if GCD(i,x)==1:
            count+=1
    return count




# =============================================================================
#   EXERCISE 2
# =============================================================================
def mod_inv2(a,b):
    dic = {'b':b,'a':a}           #I had to use dictionary because of python memory problems (it was changing b if I had put some "c=b" and used c instead)
    if a<b:
        (a,b) = (b,a)
    k  = [0,1,0]
    Xi = [0,1,0]
    i = 0
    while a%b!=0:
        k[i%3] = int(a/b)
        if i!=0 and i!=1:
            Xi[i%3] = (Xi[(i-2)%3]-int(k[(i-2)%3]*Xi[(i-1)%3]))%dic['b']
        (a,b) = (b,a%b)
        i=(i+1)
    k[i%3] = int(a/b)
    if i == 1:                      #if there's only 1 step on the euclidean algorithm, the inverse needs to be found differently
        return dic['b'] - k[0]
    Xi[i%3] = (Xi[(i-2)%3]-int(k[(i-2)%3]*Xi[(i-1)%3]))%dic['b']
    Xi[(i+1)%3] = (Xi[(i-1)%3]-int(k[(i-1)%3]*Xi[i%3]))%dic['b']
    if (Xi[(i+1)%3]*dic['a'])%dic['b'] != 1:
        return False
    return Xi[(i+1)%3]

def Ex2():
    print('1/22 mod 59 =',mod_inv2(22,59),
          '\n1/7 mod 15 =',mod_inv2(7,15),
          '\n1/49 mod 101 =', mod_inv2(49,101),
          '\n1/66 mod 123 =', mod_inv2(66,123))
    
#No, because GCD(66,123) = 3 != 1
    
    
# =============================================================================
#   EXERCISE 3
# =============================================================================
def mod_inv(a,b):
    if GCD(a,b)!=1:
        return False
    if not sympy.ntheory.primetest.isprime(b):
        return False
    return (a**(phi(b)-1))%b

def Ex3():
    print('1/22 mod 59 =',mod_inv(22,59),
          '\n1/7 mod 15 =',mod_inv(7,15),
          '\n1/49 mod 101 =', mod_inv(49,101),
          '\n1/66 mod 123 =', mod_inv(66,123))
    
#Answeer: No, because 15 is not prime (on this case)

# =============================================================================
#   EXERCISE 4
# =============================================================================
def BPM(a,b):               #Binary powering method
    '''a^b (mod c)'''
    base = a
    result = 1
    b_2 = numpy.binary_repr(b)
    while True:
        if b_2[-1] == '1':
            result = result*base
        base = base*base
        b_2 = b_2[:-1]
        if len(b_2) == 0:
            return result
        
def Ex4():
    print('5^10 =',BPM(5,10),
          '\n3^13 =',BPM(3,13),
          '\n16^5 =',BPM(16,5),
          '\n2^17 =',BPM(2,17))