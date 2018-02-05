# AES-CBC

AES-CBC模式的问题是啥？

两次加密的目的就是为了能得到中间量，这样就已知第二次加密的iv。第一次加密控制明文长度，使最后一个block的未知明文长度始终为1，比如我们知道flag最后一位是’}’,通过前面填充长度，使最后block为’}\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15‘，第一次加密后，可以得到此段明文的密文，这段密文也是下一次加密的iv，然后第二次加密遍历1字节明文，比较密文是否相等即可得到一位，以此类推。
```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from struct import *
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes,bytes_to_long
import re
from pwn import *
def PKCS5(s):
    s=s+''.join([long_to_bytes(len(s)%16) for i in range(16-len(s)%16)])
	return s
def sp(s):
	lis=[]
	for i in range(0,len(s),16):
		lis.append(s[i:i+16])
	return lis
table='0123456789abcdef'
# io=remote('112.74.55.65',4001)
flag='}'
for i in range(32):
	print i
	for x in table:
		io=remote('112.74.55.65',4001)
		io.send(('1'*(10+i)).encode('hex'))
		io.send('\n')
		io.recvuntil('ciphertext1: 0x')
		cipher1=io.recvuntil('\n').strip()		
		cl=sp(cipher1.decode('hex'))		
		iv=cl[-1]
		plain=x+flag

		c=cl[-1-len(plain)/16]
		prefix=cl[-2-len(plain)/16]

		m=strxor(strxor(prefix,PKCS5(plain)[0:16]),iv)		
		io.send(m.encode('hex'))
		io.send('\n')
		io.recvuntil('ciphertext2: 0x')
		cipher2=io.recvuntil('\n').strip()
		cl=sp(cipher2.decode('hex'))

		if cl[0]==c:
			flag=plain
			print flag
			io.close()
			break
		io.close()
		

```
