![lint_python](https://github.com/daedalus/bitcoin-recover-privkey/workflows/lint_python/badge.svg)
[![GitHub issues](https://img.shields.io/github/issues/daedalus/bitcoin-recover-privkey.svg)](https://github.com/daedalus/bitcoin-recover-privkey/issues)
[![GitHub forks](https://img.shields.io/github/forks/daedalus/bitcoin-recover-privkey.svg)](https://github.com/daedalus/bitcoin-recover-privkey/network)
[![GitHub stars](https://img.shields.io/github/stars/daedalus/bitcoin-recover-privkey.svg)](https://github.com/daedalus/bitcoin-recover-privkey/stargazers)

# bitcoin-recover-privkey
Proof of concept of bitcoin private key recovery using weak ECDSA signatures

```
Based on http://www.nilsschneider.net/2013/01/28/recovering-bitcoin-private-keys.html
Regarding Bitcoin Tx https://blockchain.info/tx/9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1.
As it's said in the previous article you need to poke around into the OP_CHECKSIG function in order to get z1 and z2,
in other hand for every other parameters you should be able to get them from the Tx itself.
```

### ECDSA math recap: ###
```
Q=dP compute public key Q where d is a secret scalar and G the base point
(x1,y1)=kP where k is random choosen an secret
r= x1 mod n
compute k**-1 or inv(k)
compute z=hash(m)
s= inv(k)(z + d) mod n
sig=k(r,s) or (r,-s mod n)
Key recovery
d = (sk-z)/r where r is the same 
```

### Try it: ###

```
python ProofOfConcept.py
```
