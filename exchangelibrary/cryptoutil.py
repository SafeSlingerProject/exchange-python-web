import sys, hashlib, binascii, struct, StringIO

#sha3 engine
if sys.version_info < (3, 4):
	import sha3

# AES Cipher
from Crypto.Cipher import AES
from Crypto import Random 

class CryptoEngine:

	@staticmethod
	def SHA3Digest(data): # static method for sha3 wrapper
		s = hashlib.new("sha3_256")
		s.update(data)
		return s.digest()
	
	# static method for cipher wrapper
	@staticmethod
	def AES256EncryptWithKey(data, nonce): 
		# enckey = sha3('1'||nonce)
		skey = '1'
		keyarray = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		enckey = CryptoEngine.SHA3Digest(keyarray)
		#print 'enckey: ', binascii.hexlify(enckey), 'len:', len(enckey)
		
		# iv = sha3('2'||nonce)
		skey = '2'
		iv = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		iv = CryptoEngine.SHA3Digest(iv)[:16]
		#print 'iv: ', binascii.hexlify(iv), 'len:', len(iv)
		
		# PCKS#7 padding
		l = len(data)
		output = StringIO.StringIO()
		val = 16 - (l % 16)
		for _ in xrange(val): output.write('%02x' % val)
		padded_data = data + binascii.unhexlify(output.getvalue())
		
		# AES CBC Cipher
		cipher = AES.new(enckey, AES.MODE_CBC, iv)
		encrypted_data = cipher.encrypt(bytes(padded_data))
		#print 'encrypted_data: ', binascii.hexlify(encrypted_data), 'len:', len(encrypted_data)
		
		return encrypted_data
	
	@staticmethod
	def AES256DecryptWithKey(data, nonce): # static method for cipher wrapper
		# deckey = sha3('1'||nonce)
		skey = '1'
		keyarray = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		deckey = CryptoEngine.SHA3Digest(keyarray)
		#print 'deckey: ', binascii.hexlify(deckey), 'len:', len(deckey)
		
		# iv = sha3('2'||nonce)
		skey = '2'
		iv = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		iv = CryptoEngine.SHA3Digest(iv)[:16]
		#print 'iv: ', binascii.hexlify(iv), 'len:', len(iv)
		
		# AES CBC Cipher
		cipher = AES.new(deckey, AES.MODE_CBC, iv)
		decipher_data = cipher.decrypt(bytes(data))
		#print 'decipher_data: ', binascii.hexlify(decipher_data), 'len:', len(decipher_data)
		
		# PCKS#7 unpadding
		nl = len(decipher_data)
		val = int(binascii.hexlify(decipher_data[-1]), 16)
		if val > 16: raise ValueError('Input is not padded or padding is corrupt')
		l = nl - val
		return decipher_data[:l]