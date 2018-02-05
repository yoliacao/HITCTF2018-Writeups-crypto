#!/usr/bin/env python
#-*- coding:utf-8 -*-
from struct import *
from Crypto.Cipher import AES
from Crypto import Random
import re
import SocketServer
import time
FLAG = 'HITCTF{' + os.urandom(16).encode('hex') + '}'
f=open('crypto400.log','a+')
class MyServer(SocketServer.StreamRequestHandler):
	"""docstring for MyServer"""
	def handle(self):		
		f.write(time.asctime()+str(self.client_address)+'\n')
		f.flush()
		pattern = '\A[0-9a-fA-F]+\Z'
		key= Random.new().read(AES.block_size)
		iv=Random.new().read(AES.block_size)
		cipher = AES.new(key,AES.MODE_CBC,iv)
		self.wfile.write('Give me the first hex value to encrypt: 0x')
		request1 = self.rfile.readline().strip()
		if len(request1) > 96 or len(request1)%2!=0 or not re.match(pattern, request1):
			self.wfile.write('invalid input, bye!\n')
			return
		plaintext1 =  PKCS5(request1.decode('hex')+ FLAG)
		ciphertext = cipher.encrypt(plaintext1)
		self.wfile.write('ciphertext1: 0x%s\n' % (ciphertext).encode('hex'))	
		self.wfile.write('Give me the second hex value to encrypt: 0x')
		request2 = self.rfile.readline().strip()
		if len(request2) > 96 or len(request1)%2!=0 or not re.match(pattern, request2):
			self.wfile.write('invalid input, bye!\n')
			return
		plaintext2 =  PKCS5(request2.decode('hex'))
		ciphertext = cipher.encrypt(plaintext2)
		self.wfile.write('ciphertext2: 0x%s\n' % (ciphertext).encode('hex'))
		self.wfile.write('Good Luck!\n')
	
		
def PKCS5(s):
	s=s+''.join([pack('B',len(s)%16) for i in range(16-len(s)%16)])
	return s

if __name__ == '__main__':
	server=SocketServer.ThreadingTCPServer(('127.0.0.1',4000),MyServer)
	server.serve_forever()
	# main()
