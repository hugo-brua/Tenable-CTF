#you can use this function ro recover private key when  there is a nonce reuse. Every values are supposed to be int

def nonce_reuse(order, s1, s2, r, hash1, hash2):
    return ((((s2 * hash1)) - ((s1 * hash2))) * pow(r*(s1-s2),-1,order))%order
