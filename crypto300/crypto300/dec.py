from Crypto.Cipher import AES,PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random.random import *
from Crypto import Random
import sys
from gmpy2 import gcd
from libnum import invmod
from secretsharing import PlaintextToHexSecretSharer as SS
keylis=[]
clis=[]
share=[]
for i in [0,2,4]:

	key=RSA.importKey(open('sk-'+str(i)+'.pem','r').read())
	keylis.append(key)
	c=open('ciphertext-' + str(i) + '.bin', 'r').read()
	share.append(key.decrypt(c.decode('base64')))
	
print share
key=SS.recover_secret(share)
print len(key),[key]
msg=open(sys.argv[1],'r').read()
iv=msg[:16]
ciphertext=msg[16:]

cipher=AES.new(key,AES.MODE_CFB,iv)
msg=cipher.decrypt(ciphertext)
open(sys.argv[1]+'.dec','w').write(msg)

# for i in keylis:
# 	for j in keylis:
# 		print gcd(i[0],j[0])
# p=28796899277235049975421947378568428888005019408631005870725337759187744546493409470582705210790627097597656481534493716225301660663533212040068163723937803169735485217437722947354732420098585958967033073629288721874028940705969141716032409906092583043329293532612601200186754187377338924379443611709918885185638934712580040042904995838353611699081350712817357237035507539201368300463060034856220488010509411264244138417348439340955309300128758040513940379009974696105387107481999359705587790254117489020540714253505694682552102843028243384677060490696214834957049391213864664165843655260698241682369402177091178720927
# p=long(2758599203)
# print keylis
# for i in range(len(keylis)):
# 	if keylis[i].n%p ==0:
# 		q=keylis[i].n/p
# 		d=invmod(keylis[i].e,(p-1)*(q-1))
# 		sk=RSA.construct((keylis[i].n,keylis[i].e,d))
# 		open('sk-'+str(i)+'.pem','w').write(sk.exportKey('PEM'))
