from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random.random import *
from Crypto import Random
import string
import sys
from secretsharing import PlaintextToHexSecretSharer as SS
key=''.join(choice(string.ascii_letters) for x in range(16))
iv=Random.new().read(AES.block_size)
cipher=AES.new(key,AES.MODE_CFB,iv)
plaintext=open(sys.argv[1],'rb').read()
msg = iv+cipher.encrypt(plaintext)
open(sys.argv[1]+'.enc','w').write(msg)
shares = SS.split_secret(key, 3, 5)

for i in range(len(shares)):
	key=RSA.importKey(open('key-'+str(i)+'.pem','r').read())
	cipher=key.encrypt(shares[i],0)[0].encode('base64')
	open('ciphertext-' + str(i) + '.bin', 'w').write(cipher)
