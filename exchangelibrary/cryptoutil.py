"""
The MIT License (MIT)

Copyright (c) 2010-2014 Carnegie Mellon University

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import sys
import binascii
import struct
import StringIO
import math
from py_sha3 import Keccak
from aes import AES

def get_roundkey_cache(key):
    if key is None:
        raise ValueError('Key is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        size = len(key)
        if size == aes.keySize['SIZE_128']:
            nbr_rounds = 10
        elif size == aes.keySize['SIZE_192']:
            nbr_rounds = 12
        elif size == aes.keySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Key size is incorrect.'
                             'Size should be 16, 24, or either 32 bytes.')
        expanded_keysize = 16 * (nbr_rounds + 1)
        return aes.expandKey(key, size, expanded_keysize)

def cbc_encrypt(cache, msg, inv=None):
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        esize = len(cache)
        if esize == aes.ekeySize['SIZE_128']:
            nbr_rounds = 10
        elif esize == aes.ekeySize['SIZE_192']:
            nbr_rounds = 12
        elif esize == aes.ekeySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Expanded key has incorrect size.'
                             'Size should be 176, 208, or either 240 bytes.')
        plaintext = []
        iput = [0] * 16
        output = []
        cipher = [0] * 16
        if inv is None:
            inv = [0] * 16
        first_round = True
        if msg is not None:
            for j in range(int(math.ceil(float(len(msg))/16))):
                start = j * 16
                end = start + 16
                if  end > len(msg):
                    end = len(msg)
                plaintext = msg[start:end]
                for i in range(16):
                    if first_round:
                        iput[i] = plaintext[i] ^ inv[i]
                    else:
                        iput[i] = plaintext[i] ^ cipher[i]
                first_round = False
                cipher = aes.encrypt(iput, cache, nbr_rounds)
                output.extend(cipher)
        return struct.pack('B' * len(output), *output)

def cbc_decrypt(cache, cipher, inv=None):
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif cipher is None:
        raise ValueError('Ciphertext is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        esize = len(cache)
        if esize == aes.ekeySize['SIZE_128']:
            nbr_rounds = 10
        elif esize == aes.ekeySize['SIZE_192']:
            nbr_rounds = 12
        elif esize == aes.ekeySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Expanded key has size incorrect.'
                             'Size should be 176, 208, or either 240 bytes.')
        # the AES input/output
        ciphertext = []
        iput = []
        output = []
        plaintext = [0] * 16
        # the output plain text string
        string_out = bytes()
        if inv is None:
            inv = [0] * 16
        # char firstRound
        first_round = True
        if cipher != None:
            for j in range(int(math.ceil(float(len(cipher))/16))):
                start = j * 16
                end = start + 16
                if j * 16 + 16 > len(cipher):
                    end = len(cipher)
                ciphertext = cipher[start:end]
                output = aes.decrypt(ciphertext, cache, nbr_rounds)
                for i in range(16):
                    if first_round:
                        plaintext[i] = inv[i] ^ output[i]
                    else:
                        plaintext[i] = iput[i] ^ output[i]
                first_round = False
                string_out += struct.pack('B' *len(plaintext), *plaintext)
                iput = ciphertext
        return string_out

class CryptoEngine:

	@staticmethod
	def sha3_digest(dat=None):
	    return Keccak(c=512, r=1088, n=256, data=dat).hexdigest().decode('hex')
	
	@staticmethod
	def aes256_cbc_encryption(data, nonce): 
	    # enckey = sha3('1'||nonce)
	    skey = '1'
	    keyarray = struct.pack('1s%dB' % len(nonce), skey, *nonce)
	    enckey = CryptoEngine.sha3_digest(keyarray)
	    
	    # iv = sha3('2'||nonce)
	    skey = '2'
	    iv = struct.pack('1s%dB' % len(nonce), skey, *nonce)
	    iv = CryptoEngine.sha3_digest(iv)[:16]
	    
	    # PCKS#7 padding
	    l = len(data)
	    output = StringIO.StringIO()
	    val = 16 - (l % 16)
	    for _ in xrange(val): output.write('%02x' % val)
	    padded_data = data + binascii.unhexlify(output.getvalue())
	    
	    # AES CBC Cipher
	    roundkey = get_roundkey_cache(bytearray(enckey))
	    encrypted_data = cbc_encrypt(roundkey, bytearray(padded_data), bytearray(iv))
	    #print 'encrypted_data: ', binascii.hexlify(encrypted_data), 'len:', len(encrypted_data)
	    return encrypted_data

	@staticmethod
	def aes256_cbc_decryption(data, nonce): # static method for cipher wrapper
		# deckey = sha3('1'||nonce)
		skey = '1'
		keyarray = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		deckey = CryptoEngine.sha3_digest(keyarray)
		#print 'deckey: ', binascii.hexlify(deckey), 'len:', len(deckey)
		
		# iv = sha3('2'||nonce)
		skey = '2'
		iv = struct.pack('1s%dB' % len(nonce), skey, *nonce)
		iv = CryptoEngine.sha3_digest(iv)[:16]
		#print 'iv: ', binascii.hexlify(iv), 'len:', len(iv)
		
		# AES CBC Cipher
		roundkey = get_roundkey_cache(bytearray(deckey))
		decipher_data = cbc_decrypt(roundkey, bytearray(data), bytearray(iv))
		
		# PCKS#7 unpadding
		nl = len(decipher_data)
		val = int(binascii.hexlify(decipher_data[-1]), 16)
		if val > 16: raise ValueError('Input is not padded or padding is corrupt')
		l = nl - val
		return decipher_data[:l]


