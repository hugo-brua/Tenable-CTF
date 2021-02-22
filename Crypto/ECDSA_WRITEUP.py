#ECDSA IMPLEMENTATION

#What we had:
import ecdsa
import random
from Crypto.Cipher import AES
import binascii

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

gen = ecdsa.NIST256p.generator
order = gen.order()
secret = random.randrange(1,order)
 
pub_key = ecdsa.ecdsa.Public_key(gen, gen * secret)
priv_key = ecdsa.ecdsa.Private_key(pub_key, secret)
 
nonce1 = random.randrange(1, 2**127)
nonce2 = nonce1
 
# randomly generate hash value
hash1 = random.randrange(1, order)
hash2 = random.randrange(1, order)
 
sig1 = priv_key.sign(hash1, nonce1)
sig2 = priv_key.sign(hash2, nonce2)

s1 = sig1.s
s2 = sig2.s

print("r: " + str(sig1.r))
print("s1: " + str(s1))
print("s2: " + str(s2))
print("")
print("hashes:")
print(hash1)
print(hash2)
print("")
print("order: " + str(order))
print("")

aes_key = secret.to_bytes(64, byteorder='little')[0:16]

ptxt =  pad("flag{example}")
IV = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
cipher = AES.new(aes_key, AES.MODE_CBC, IV)
ctxt = cipher.encrypt(ptxt.encode('utf-8'))

print("Encrypted Flag:")
print(binascii.hexlify(ctxt))

Output File Contents:

r: 50394691958404671760038142322836584427075094292966481588111912351250929073849
s1: 26685296872928422980209331126861228951100823826633336689685109679472227918891
s2: 40762052781056121604891649645502377037837029273276315084687606790921202237960

hashes:
777971358777664237997807487843929900983351335441289679035928005996851307115
91840683637030200077344423945857298017410109326488651848157059631440788354195

order: 115792089210356248762697446949407573529996955224135760342422259061068512044369

Encrypted Flag:
b'f3ccfd5877ec7eb886d5f9372e97224c43f4412ca8eaeb567f9b20dd5e0aabd5


"""
So, the goal is to find the private key to decrypt the encrypted flag.
After analyzing the code, we notice that both hashes of the output used the same nonce so we guess that's a nonce reuse.
For the little story, a vulnerability of this type was found in Sony's Playstation 3 https://www.bbc.com/news/technology-12116051
I will explain the mathematical principle of the attack here, but if you don't care i'll give you my code at the end, you'll just have to copy paste it to reuse it, but 
I would advise you to understand the principle.

Mathematical part:

Let H1 and H2 be the hashes, priv the private key we are searching for, s1 the first number of first signature, s2 the first number of second signature,
order the order, K (here named secret) the unknown value generated randomly between 1 and order-1, and r the unique second number of both signatures.

We have 2 equations :
s1 = k^(-1) * (hash1 + priv *R)  % order (1)
s2 = k^(-1) * (hash2 + priv *R)  % order (2)
So it means that (if we multiply by K (1) and (2) and divide (1) by s1 and (2) by s2 to make k disappear of the equations):

(hash2 + priv * R)/s2 = (hash1 + priv * R)/s1 % order

So we have here 1 equation and 1 unknow value, we just have to isolate it and it gives us :
priv = (s2 * hash1 - s2 * hash2) * (r*(s1-s2)**-1 %order))
(r*(s1-s2)**-1 %order)) is the inverse of (r*(s1-s2)) modulo order, that means the number that satisfies r*(s1-s2) = 1 % order
Code of the function :
"""
def nonce_reuse(order, s1, s2, r, hash1, hash2):
    return ((((s2 * hash1)) - ((s1 * hash2))) * pow(r*(s1-s2),-1,order))%order

"""
To go further :

You can crack the key too knowing K.
I don't know why but I first thought that we had K value here. 
If you want to learn more about it, this link is very good
https://medium.com/asecuritysite-when-bob-met-alice/cracking-ecdsa-with-a-leak-of-the-random-nonce-d72c67f201cd



"""
















