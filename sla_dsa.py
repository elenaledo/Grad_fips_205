#!/bin/python3 
#print ('hello world')

import hashlib
import os
import enum
import math

class parameter:
        n       = 1
        h       = 2
        d       = 3
        h_prime = 4
        a       = 5
        k       = 6
        lg_w    = 7
        m       = 8
        w       = 2**lg_w
        len_1   = math.ceil((8*n)/lg_w)
        len_2   = math.floor((math.log(len_1*(w-1),2)/lg_w) +1)
        len     = len_1 + len_2


def toInt(X,n):
    # convert a byte string to an integer
    total = 0
    for i in range(0,n-1):
        total = 256*total + X[i]
    return total

def toByte(x,n):
    # convert an integer to a byte string
    total = x
    for i in range(0,n-1):
        S[n-1-i] = total%256
        total = total>>8
    return S

def base_2b(X,b,out_len):
    # Compute the base 2 representation of X
    index = 0
    bits = 0
    total = 0
    for out in range(0,out_len-1):
        while bits < b:
            total = (total << 8) + X[index]
            index = index + 1
            bits = bits + 8
        bits = bits - b
        baseb[out] = (total>>bits)%(2**b)
    return baseb

def chain(X,i,s,PK_seed, ADRS):
    # chain function used in WOTS+
    if((i+s)>=w):
        return NULL
        #break
    tmp = X
    for j in range(i,i+s-1):
        ADRS.setHashAddress(j)
        tmp = F(PK_seed, ADRS, tmp)
    return tmp

#def wots_PKgen(SK_seed, PK_seed, ADRS):
#    # Generate WOTS+ public key
#    sk_ADRS =  ADRS
#    sk_ADRS.setTypeAndClear(wots_prf)

def PRFmsg(seed, opt_rand, message):
    m = hashlib.sha256()
    m.update(seed)
    m.update(opt_rand)
    m.update(message)
    return m.digest()

def Hmsg(R, PK_seed, PK_root, M):
    m = hashlib.sha256()
    m.update(R)
    m.update(PK_seed)
    m.update(PK_root)
    m.update(M)
    return m.digest()
#def PRF(PK_seed, SK_seed, ADRS)
    # PRF is used to generate a secret values in WOTS+ and FORS private key
#    return
#def T_l(PK_seed, ADRS, M_l)
    # Hash function map an ln-byte message to an n-byte message
#   return
#def H(PK_seed, ADRS,M_2)
    # Special case of T_l take 2n-byte message to n-byte message
#   return
#def F(PK_seed, ADRS, M_1)
    # Hash function take n_byte message input and produces n-byte output
#   return
def FORS_sign(digest, SK_seed, ADRS):
    # Simplified FORS signature function
    m = hashlib.sha256()
    m.update(SK_seed)
    m.update(ADRS)
    m.update(digest)
    return m.digest()

def get_FORS_PK(SIGFORS, PK_seed, ADRS):
    # Simplified function for obtaining FORS public key
    m = hashlib.sha256()
    m.update(PK_seed)
    m.update(ADRS)
    m.update(SIGFORS)
    return m.digest()

def HT_sign(FORS_PK, SK_seed, ADRS):
    # Simplified hypertree signature function
    m = hashlib.sha256()
    m.update(SK_seed)
    m.update(ADRS)
    m.update(FORS_PK)
    return m.digest()

def slh_sign(M, SK):
    SK_seed, SK_prf, PK_seed, PK_root = SK
    ADRS = os.urandom(32)  # Randomly generated address
    opt_rand = PK_seed  # Set opt_rand to PK.seed

    # Generate randomizer
    R = PRFmsg(SK_prf, opt_rand, M)
    SIG = [R]

    # Compute message digest
    digest = Hmsg(R, PK_seed, PK_root, M)

    # Compute FORS signature
    SIGFORS = FORS_sign(digest, SK_seed, ADRS)
    SIG.append(SIGFORS)

    # Obtain corresponding FORS public key
    FORS_PK = get_FORS_PK(SIGFORS, PK_seed, ADRS)

    # Sign the FORS public key
    SIGHT = HT_sign(FORS_PK, SK_seed, ADRS)
    SIG.append(SIGHT)

    return SIG

#def slh_verify(M,SIG,PK):
#    if 
#    return false
#    end if


# Example usage
SK_seed = os.urandom(32)
SK_prf = os.urandom(32)
PK_seed = os.urandom(32)
PK_root = os.urandom(32)
SK = (SK_seed, SK_prf, PK_seed, PK_root)
M = b"Hello, This is Thu Le , testing for slh_dsa"

# Generate SLH-DSA signature
signature = slh_sign(M, SK)
#print("Parameter: ", parameter.a, parameter.m, "\n")
print("Message: ", M,"\n")
print("SK_seed: ", SK_seed,"\n")
print("SK_prf: ", SK_prf,"\n")
print("PK_seed: ", PK_seed,"\n")
print("PK_root: ", PK_root,"\n")
print("SK: ", SK,"\n")
print("SLH-DSA Signature: ", signature,"\n")
