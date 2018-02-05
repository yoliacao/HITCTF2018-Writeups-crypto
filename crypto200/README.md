# EASY_XOR

听说密码学课上讲了流密码，密码复用可是这种加密体系最大的隐患，不知道你对于线性反馈移位寄存器可否了解呢？
./enc.py HITCTF{XXXXXXXXXXXX} enc.py
./enc.py HITCTF{XXXXXXXXXXXX} lfsr.txt


此题由于出题人一时疏忽留下了一个漏洞，收了WP才发现。。。还是请允许我介绍一下正确的打开方式。
首先通过亦或得到enc.py的前半段应该是这样的
```python
#!/usr/bin/env python3

import sys

magic = [106 >> i & 1 for i in range(8)]
block = 32
n = 8 * block

def next(x):
    x = (x & 1) << n+1 | x << 1 | x >> n-1
	y = 0
	for i in range(n):
		y |= magic[(x >> i) & 7] << i
	return y

keystream = int.from_bytes(sys.argv[1].encode(),'little')

for
```
并且根据题目描述，可以知道这是流密码，next函数是每块加密后派生新key的伪随机函数，其结构就是线性反馈移位寄存器。漏洞就出在magic矩阵上。通过亦或明文密文得到一个key序列，并且使用next函数得到之后的key，还原enc.py全文。
```python
#!/usr/bin/env python3

import sys

magic = [106 >> i & 1 for i in range(8)]
block = 32
n = 8 * block

def next(x):
    x = (x & 1) << n+1 | x << 1 | x >> n-1
	y = 0
	for i in range(n):
		y |= magic[(x >> i) & 7] << i
	return y

keystream = int.from_bytes(sys.argv[1].encode(),'little')

for i in range(n//2):	
	keystream = next(keystream)

f=open(sys.argv[2])
plaintext = f.read(block).encode()
r=open(sys.argv[2]+'.enc','wb')
while plaintext:
	cipher=(((int.from_bytes(plaintext,'little')) ^ keystream).to_bytes(block,'little'))
	r.write(cipher)
	keystream = next(keystream)
	plaintext = f.read(block).encode()
r.close()
f.close()
```
发现在加密明文前，输入的key现迭代了128次。要得到原始输入的key要逆向next函数。解密脚本如下。
```python
#!/usr/bin/env python3

RULE = [106 >> i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES

def dnext(x):
    res=0
	a255=(x>>(N-1))&1
	a254=(x>>(N-2))&1
	a0=(x&1)
	reslis=[]
	for i in range(8):
		if RULE[i]==a255:
			if RULE[(i<<1)&7]==a254 or RULE[((i<<1)+1)&7]==a254:
				if RULE[i>>1]==a0 or RULE[(i>>1)+4]==a0:
					reslis.append(i)
	for res in reslis:
		print(res)
		for i in range(1,N):
			a=(x>>N-i-1)&1
			b=(res<<1)&7		
			if RULE[b]==a:
				res=res<<1
			elif RULE[b+1]==a:
				res=(res<<1)+1
			else:
				print('error')
				break
		if res&3 == res>>N:
			return (res>>1)&(2**256-1)
		else:
			continue
	return -1
def next(x):
	x = (x & 1) << N+1 | x << 1 | x >> N-1
	y = 0
	for i in range(N):
		y |= RULE[(x >> i) & 7] << i
	return y
def find_k0(c,m):
	return int.from_bytes(c,'little')^int.from_bytes(m,'little')
c=open('lfsr.txt','rb').read(32)
m=open('lfsr.txt.enc','rb').read(32)
keystream=find_k0(c,m)
for i in range(N//2):
	kst= dnext(keystream)
	assert(next(kst)==keystream)
	keystream=kst
	print(keystream)
	print(keystream.to_bytes(32,'little'))
```

