#!/usr/bin/env python
#-*- coding:utf-8 -*-
import os,sys
import hashlib
from gmpy2 import *
from Crypto.Util import number
from Crypto import Random
from Crypto.PublicKey.pubkey import *
import SocketServer

FLAG = 'HITCTF{' + os.urandom(16).encode('hex') + '}'
MSGLENGTH = 40000
HASHLENGTH = 16

def sign(m, sk, pk, p, g):
    kk=getPrime(15)
    k = ( kk* next_prime(pow(pk, sk, p)) )%(p-1)
    pr(kk)
    r = pow(g, k, p)
    s = (pow((m - sk * r),1,p-1) * inverse(k, p-1)) % (p-1)
    return r, s

def verify(m, r, s, pk, p, g):
    if r < 1: return False
    if (pow(pk, r, p) * pow(r, s, p)) % p == pow(g, m, p):
        return True
    return False

def generate_keys():
    randomFunc = Random.new().read
    while True:
        q = bignum(getPrime(512))
        # generate a safe prime
        p = 2 * q + 1
        if number.isPrime(p, 1e-6, randomFunc):
            break
    while True:
        g = number.getRandomRange(3, p, randomFunc)
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        if (p - 1) % g == 0:
            continue
        g_inv = number.inverse(g, p)
        if (p - 1) % g_inv == 0:
            continue
        break
    sk = number.getRandomRange(2, p - 1, randomFunc)
    pk = pow(g, sk, p)
    return pk, sk, g, p

def digitalize(m):
    return int(m.encode('hex'), 16)

class MyServer(SocketServer.StreamRequestHandler):
    """docstring for MyServer"""
    def handle(self):
        Random.atfork()
        proof = (os.urandom(12)).encode('base64')[:-1]
        self.wfile.write("为了证明您的身份，请输入一个以:%s开头，长度为%d的字符串，使其SHA1校验和尾存在16比特0" % (proof,len(proof) + 5))
        test=self.rfile.readline()
        test=test[:21]
        ha = hashlib.sha1()
        ha.update(test)
        if (test[0:16] != proof or ord(ha.digest()[-1]) != 0 or ord(ha.digest()[-2]) != 0): # or ord(ha.digest()[-3]) != 0 or ord(ha.digest()[-4]) != 0):
            self.wfile.write("登陆失败")
            return
        self.wfile.write('=== 欢迎光临DSA登陆系统 ===\n您有三次机会来登陆\n')
        pk, sk, g, p = generate_keys()
        self.wfile.write("本次通信的公钥为: %s" % repr([p, g, pk]))
        self.wfile.write(sk)
        for it in range(3):
            self.wfile.write("用户名:")
            msg=self.rfile.readline().strip()
            self.wfile.write(digitalize(msg))
            if len(msg) > MSGLENGTH:
                self.wfile.write("喵喵喵?")
                return
            if msg[:4] == "test":
                r, s = sign(digitalize(msg), sk, pk, p, g)

                self.wfile.write("您的签名是" + repr((hex(r), hex(s))) + "\n")
            else:
                if msg == "Administrator" + test:
                    self.wfile.write("签名:")
                    sig=self.rfile.readline().strip()
                    if len(sig) > MSGLENGTH:
                        self.wfile.write("喵喵喵?")
                        return
                    sig_rs = sig.split(",")
                    if len(sig_rs) < 2:
                        self.wfile.write(u"喵喵喵?")
                        return
                    if verify(digitalize(msg), int(sig_rs[0]), int(sig_rs[1]), pk, p, g):
                        self.wfile.write("登陆成功，有重要的信息给您: " + FLAG)
                        return
                    else:
                        self.wfile.write("你不是管理员!\n")
if __name__ == "__main__":
    server=SocketServer.ThreadingTCPServer(('127.0.0.1',4000),MyServer)
    server.serve_forever()