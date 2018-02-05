##网管的小皂片
不知道啥时候偷来一张网管的小皂片，快拿去不谢～
flag格式HITCTF{图片中句子区分大小写空格转'_'}
HITCTF{I_don't_need_Google_my_life_knows_everything!}

5个存在弱点的公钥，首先使用openssl，或者任何语言的标准加解密库从证书文件中提取RSA公钥中的N和E，其中key-0和key-4存在公因子，可以解出私钥，key-2存在极小的P，可以通过在线查表查到，或者直接遍历出来。

    做到这里其实已经可以解题了，因为设置了shamir的陷门函数，AES加密的密钥被分解成5个信息，得到任意三个就可还原。然后逆流程即可得到网管的小照片一张，flag就在他的衣服上。
* Key-0 和 Key-4存在公因子
* Key-1 可以通过 Fermat Method被分解
* Key-2 存在极小素数因子， 所以可以通过查 factordb.com 或者使用 ECM Method.
* Key-3 Wiener's Attack

```python
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import sys
from secretsharing import PlaintextToHexSecretSharer as SS
keylis=[]
clis=[]
share=[]
for i in [0,2,4]:
    key=RSA.importKey(open('key-'+str(i)+'.pem','r').read())
	keylis.append(key)
	c=open('ciphertext-' + str(i) + '.bin', 'r').read()
	share.append(key.decrypt(c.decode('base64')))
key=SS.recover_secret(share)
msg=open(sys.argv[1],'r').read()
iv=msg[:16]
ciphertext=msg[16:]

cipher=AES.new(key,AES.MODE_CFB,iv)
msg=cipher.decrypt(ciphertext)
open(sys.argv[1]+'.dec','w').write(msg)
```

