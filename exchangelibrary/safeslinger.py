"""
The MIT License (MIT)

Copyright (c) 2010-2015 Carnegie Mellon University

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

import os
import struct
import binascii
import random
import sys
import time

from cryptoutil import CryptoEngine
from httpsclient import HTTPClient
from dh import DiffieHellman

class SafeSlingerExchange:
    # constants
    MINI_USERS = 2
    NONCE_LEN = 32

    def __init__(self, address="slinger-dev.appspot.com"):
        # networking object
        self.version = 1 << 24 | 8 << 16
        self.address = address
        self.httpclient = None
        # predefined data structures
        self.match_nonce = None
        self.wrong_nonce = None
        self.match_extrahash = None
        self.match_hash = None
        self.encrypted_data = None
        self.protocol_commitment = None
        self.dhkey = None
        self.dhpubkey = None
        self.data_commitment = None
        self.num_users = 0
        self.userID = None
        self.correct_index = -1
        self.selected_index = -1
        self.dhkey_len = -1
        self.groupkey = None
        self.uidSet = []
        self.dataCommitmentSet = {}
        self.protoCommitmentSet = {}
        self.dhpubkeySet = {}
        self.receivedcipherSet = {}
        self.matchExtraHashSet = {}
        self.wrongHashSet = {}
        self.matchHashSet = {}
        self.keyNodes = {}
        self.matchNonceSet = {}
        # load dictionary files
        ins = open( "odd-dict.txt", "r" )
        self.odd_array = []
        for line in ins:
            self.odd_array.append( line.rstrip() )
        ins.close()
        ins = open( "even-dict.txt", "r" )
        self.even_array = []
        for line in ins:
    	    self.even_array.append( line.rstrip() )
    	ins.close()
    
    def SelecGroupSize(self):
    	while True:
    		try:
    			numUsers = int(raw_input("How many users in the exchange? [2-10] "))
    			if numUsers >= 2 and numUsers <=10:
    				self.num_users = numUsers
    				break
    			else:
    				print "A minimum of %d members are required to exchange data." % SafeSlingerExchange.MINI_USERS
    		except Exception:
    			print "A minimum of %d members are required to exchange data." % SafeSlingerExchange.MINI_USERS
    
    def BeginExchange(self, data):
    	self.match_nonce = os.urandom(SafeSlingerExchange.NONCE_LEN)
    	self.wrong_nonce = os.urandom(SafeSlingerExchange.NONCE_LEN)
    	# match_extrahash = sha3(match_nonce)
    	self.match_extrahash = CryptoEngine.sha3_digest(self.match_nonce)
    	# wrong_hash = sha3(wrong_nonce)
    	self.wrong_hash = CryptoEngine.sha3_digest(self.wrong_nonce)
    	# match_hash = sha3(match_extrahash)
    	self.match_hash = CryptoEngine.sha3_digest(self.match_extrahash)
    	# encrypted_data = aes_cbc(enckey, exchange_data)
    	self.encrypted_data = CryptoEngine.aes256_cbc_encryption(data, self.match_nonce)
    	#compute protocol_commitment = sha3(match_hash||wrong_hash)
    	self.protocol_commitment = CryptoEngine.sha3_digest(self.match_hash + self.wrong_hash)
    	# generate Diffie Hellman Key
    	self.dhkey = DiffieHellman()
    	self.dhpubkey = self.dhkey.getHexData(self.dhkey.publicKey).strip()
    	self.dhkey_len = len(self.dhpubkey)
    	# data_commitment = sha3(protocol_commitment||DHPubKey||encrypted_data)
    	self.data_commitment = CryptoEngine.sha3_digest(self.protocol_commitment+self.dhpubkey+self.encrypted_data)
    	# initialize network object
    	self.httpclient = HTTPClient(self.address)
    
    def AssignUser(self):
    	datagram = self.httpclient.assign_user(self.data_commitment)
    	userID = (struct.unpack("!i", datagram[0:4]))[0]
    	self.userID = userID
    	# store parameters
    	self.dataCommitmentSet[userID] = self.data_commitment
    	self.protoCommitmentSet[userID] = self.protocol_commitment
    	self.dhpubkeySet[userID] = self.dhpubkey
    	self.receivedcipherSet[userID] = self.encrypted_data
    	print ("Assigned ID = %d.\n\nThis number is used to create a unique group of users. Compare, and then enter the lowest number." % self.userID )
    
    def SelectLowestNumber(self):
    	low_num = -1
    	while True:
    		try:
    			low_num = int(raw_input("Enter Lowest Number: "))
    			if low_num > 0: 
    				break
    			else:
    				print 'Please enter a positive integer.'
    		except Exception:
    			print 'Please enter a positive integer.'
    	
    	print "%d users, Lowest %d\nRequesting Membership..." % (self.num_users, low_num)
    	numUsers_Recv = 1
    	self.uidSet[:] = []
    	self.uidSet.insert(0, self.userID)
    	retry = 0
    	while (numUsers_Recv < self.num_users):
    		datagram = self.httpclient.send_minid(self.userID, 
    		                                      low_num, 
    		                                      self.uidSet, 
    		                                      self.data_commitment)
    		minVersion = (struct.unpack("!i", datagram[0:4]))[0]
    		count = (struct.unpack("!i", datagram[4:8]))[0]
    		delta_count = (struct.unpack("!i", datagram[8:12]))[0]
    		# Collect all data commitments Ci from other users
    		if delta_count > 0:
    			offset = 12
    			for i in range(delta_count):
    				uid = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				self.uidSet.append(uid)
    				offset += 4
    				commitLen = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				offset += 4
    				self.dataCommitmentSet[uid] = struct.unpack("%dB" %commitLen, datagram[offset:offset+commitLen])
    				offset += commitLen
    				numUsers_Recv += 1
    				print "Received (%d/%d) Items" % (numUsers_Recv, self.num_users-1)
    		retry += 1
    		time.sleep(retry)
    		if retry >= 10:
    			print "Error: reached maximum retries"
    			quit()
    	self.SyncData()
    
    def SyncData(self):
    	print "Waiting for all users to join..."
    	numUsers_Recv = 1
    	self.uidSet[:] = []
    	self.uidSet.insert(0, self.userID)
    	retry = 0
    	while (numUsers_Recv < self.num_users):
    		datagram = self.httpclient.sync_data(self.userID,
    		                                    self.uidSet,
    		                                    self.protocol_commitment,
    		                                    self.dhpubkey,
    		                                    self.encrypted_data)
    		count = (struct.unpack("!i", datagram[0:4]))[0]
    		delta_count = (struct.unpack("!i", datagram[4:8]))[0]
    		# Collect all data commitments Ci from other users
    		if delta_count > 0:
    			offset = 8
    			for i in range(delta_count):
    				uid = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				self.uidSet.append(uid)
    				offset += 4 # proto commitment
    				total_len = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				offset += 4
    				self.protoCommitmentSet[uid] = struct.unpack("%dB" % SafeSlingerExchange.NONCE_LEN, datagram[offset:offset+SafeSlingerExchange.NONCE_LEN])
    				offset += SafeSlingerExchange.NONCE_LEN
    				#dhkey
    				self.dhpubkeySet[uid]  = struct.unpack("%dB" % self.dhkey_len, datagram[offset:offset+self.dhkey_len])
    				offset += self.dhkey_len
    				# encrypted_dataSet
    				encrypted_len = total_len-SafeSlingerExchange.NONCE_LEN-self.dhkey_len
    				self.receivedcipherSet[uid] = struct.unpack("%dB" % encrypted_len, datagram[offset:offset+encrypted_len])
    				offset += encrypted_len
    				numUsers_Recv += 1
    				print "Received (%d/%d) commitments" % (numUsers_Recv, self.num_users)
    		retry += 1
    		time.sleep(retry)
    		if retry >= 10:
    			print "Error: reached maximum retries"
    			quit()
    
    
    def Compute3Wordphrases(self):
    	#compute 3-word phrases, step 1 compute hash
    	total_len = 0
    	self.uidSet.sort()
    	buffer = bytearray()
    	
    	for x in self.uidSet:
    		buffer.extend(self.protoCommitmentSet[x])
    		buffer.extend(self.dhpubkeySet[x])
    		buffer.extend(self.receivedcipherSet[x])
    	
    	#print 'buffer: ', binascii.hexlify(buffer)
    	wordhash = CryptoEngine.sha3_digest(bytes(buffer))
    	#print 'word hash: ', binascii.hexlify(wordhash)
    	del buffer
    	
    	# generate 3-word phrases
    	hashint = [0, 0, 0, 0, 0, 0]
    	# create empty byte array
    	evenVec = bytearray(256)
    	oddVec = bytearray(256)
    	evenVec[ord(wordhash[0])] = 1 # set to True
    	oddVec[ord(wordhash[1])] = 1
    	evenVec[ord(wordhash[2])] = 1
    	
    	# essentially need to sort list of user ids first
    	# generate wordlist for every user id up to ours
    	# then generate our wordlist
    	count = 0
    	foundUser = False
    	hasharray = None
    	decoy1 = None
    	decoy2 = None
    	
    	for x in self.uidSet:
    		if x == self.userID: foundUser = True
    		# unsigned char *buf = malloc(HASHLEN + 1); 
    		buf = bytearray()
    		buf.append(count)
    		buf.extend(wordhash)
    		whash = CryptoEngine.sha3_digest(bytes(buf))
    		hasharray = bytearray(whash)
    		del buf
    		
    		# 2 decoy wordlists for each user
    		for d in range(2):
    			while evenVec[hasharray[0 + 3*d]] == 1:
    				if hasharray[0 + 3*d] == 255: hasharray[0 + 3*d] = hasharray[0 + 3*d] - 255
    				else: hasharray[0 + 3*d] = hasharray[0 + 3*d] + 1
    			while oddVec[hasharray[1 + 3*d]] == 1:
    				if hasharray[1 + 3*d] == 255: hasharray[1 + 3*d] = hasharray[1 + 3*d] - 255
    				else: hasharray[1 + 3*d] = hasharray[1 + 3*d] + 1
    			while evenVec[hasharray[2+ 3*d]] == 1:
    				if hasharray[2 + 3*d] == 255: hasharray[2 + 3*d] = hasharray[2 + 3*d] - 255
    				else: hasharray[2 + 3*d] = hasharray[2 + 3*d] + 1
    			#print 'modified hasharray hash: ', binascii.hexlify(hasharray), 'len:', len(hasharray)
    			evenVec[hasharray[0+3*d]] = 1
    			oddVec[hasharray[1+3*d]] = 1
    			evenVec[hasharray[2+3*d]] = 1     
    			# compute decoy strings only if user is found
    			if (d == 0) and (foundUser == True):
    				hashint[0] = hasharray[0]
    				hashint[1] = hasharray[1]
    				hashint[2] = hasharray[2]
    				decoy1 = "%s   %s   %s" % (self.even_array[hashint[0]], self.odd_array[hashint[1]], self.even_array[hashint[2]])
    			elif foundUser == True:
    				hashint[3] = hasharray[3]
    				hashint[4] = hasharray[4]
    				hashint[5] = hasharray[5]
    				decoy2 = "%s   %s   %s" %(self.even_array[hashint[3]], self.odd_array[hashint[4]], self.even_array[hashint[5]])
    		#end of d loop
    		if foundUser == True: break
    		count = count + 1
    	#end of x loop
    	
    	# to set the correct wordlist at some random position
    	self.correct_index = random.randint(0, sys.maxint) % 3
    	#print 'correct_index = ', self.correct_index
    	
    	d1Added = False
    	wordlist_labels = []
    	numberlist_labels = []
    	hashbytes = bytearray(wordhash)
    	number = 0
    	# numeric labels
    	for i in range(3):
    		numberstr = ''
    		if i == self.correct_index:
    			for j in range(3):
    				number = hashbytes[j]
    				if (j % 2) != 0: number = number + 256
    				number = number + 1
    				numberstr = numberstr+"%d   "%(number)
    		else:
    			if not d1Added:
    				for j in range(3):
    					number = hashint[j]
    					if (j % 2) != 0: number = number + 256
    					number = number + 1
    					numberstr = numberstr+"%d   "%(number)
    				d1Added = True
    			else:
    				for j in range(3):
    					number = hashint[j+3]
    					if (j % 2) != 0: number = number + 256
    					number = number + 1
    					numberstr = numberstr+"%d   "%(number)
    		numberlist_labels.append(numberstr)
    	
    	d1Added = False
    	for i in range(3):
    		if i == self.correct_index:
    			# correct phrases
    			correct_phrase = "%s   %s   %s" % (self.even_array[hashbytes[0]], self.odd_array[hashbytes[1]], self.even_array[hashbytes[2]])
    			wordlist_labels.append(correct_phrase)
    		else:
    			if not d1Added:
    				wordlist_labels.append(decoy1)
    				d1Added = True
    			else:
    				wordlist_labels.append(decoy2)
    	print "All phones must match one of the 3-word phrases. Compare, and then pick the matching phrase."
    	print "[-1]: No Match."
    	for i in range(3):
    		print "[%d]: %s (%s)" % (i, wordlist_labels[i], numberlist_labels[i])
    	while True:
    		try:
    			idx = int(raw_input("Enter the index number to show your decision:"))
    			if idx <= 2 and idx >= -1 : 
    				self.selected_index = idx
    				break
    			else:
    				print 'Enter a correct index!'
    		except Exception:
    			print 'Not an integer number!'
    	print "Waiting for verification from all members..."
    
    def PhrasesVerification(self):
    	if self.selected_index == self.correct_index:
    		numUsers_Recv = 1
    		del self.uidSet[:]
    		self.uidSet.insert(0, self.userID)
    		while (numUsers_Recv < self.num_users):
    			datagram = self.httpclient.sync_signatures(self.userID,
    			                                           self.uidSet,
    			                                           self.match_extrahash,
    			                                           self.wrong_hash)
    			# match_extrahash || wrong_hash
    			count = (struct.unpack("!i", datagram[0:4]))[0]
    			delta_count = (struct.unpack("!i", datagram[4:8]))[0]
    			# Collect all data commitments Ci from other users
    			if delta_count > 0:
    				offset = 8
    				for i in range(delta_count):
    					uid = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    					self.uidSet.append(uid)
    					offset += 4
    					# proto commitment
    					total_len = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    					offset += 4
    					# Nmh
    					Nmh = struct.unpack("%dB" % SafeSlingerExchange.NONCE_LEN, datagram[offset:offset+SafeSlingerExchange.NONCE_LEN])
    					offset += SafeSlingerExchange.NONCE_LEN
    					# Sha3Nmh
    					Sha3Nmh = CryptoEngine.sha3_digest(bytes(bytearray(Nmh)))
    					# wH
    					wH = struct.unpack("%dB" % SafeSlingerExchange.NONCE_LEN, datagram[offset:offset+SafeSlingerExchange.NONCE_LEN])
    					offset += SafeSlingerExchange.NONCE_LEN
    					buf = bytearray(Sha3Nmh)
    					buf.extend(wH)
    					cPC = CryptoEngine.sha3_digest(bytes(buf))
    					del buf
    					rPC = self.protoCommitmentSet[uid]
    					# verify if protocol commitments match
    					# also make sure that neither is nil
    					if cPC == bytearray(rPC):
    						print "Recievd (%d/%d) Match nonces" % (numUsers_Recv, self.num_users)
    						self.matchExtraHashSet[uid] = Nmh
    						self.wrongHashSet[uid] = wH
    						self.matchHashSet[uid] = Sha3Nmh
    					else:
    						print "Someone reported a difference in phrases. Begin the exchange again."
    						return False
    					numUsers_Recv += 1
    		return True
    	else:
    		ret = self.httpclient.sync_signatures(self.userID,
    		                                      self.uidSet,
    		                                      self.match_hash,
    		                                      self.wrong_nonce)
    		return False
    		
    def handleSyncKeyNodes(self, datagram):
    	position = 0
    	for x in self.uidSet:
    		if x == self.userID:
    			break
    		else:
    			position += 1
    	
    	if position == 0 or position == 1:
    		return
    	else:
    		keyNodeFound = (struct.unpack("!i", datagram[0:4]))[0]
    		if keyNodeFound > 0:
    			keyNodeLen = (struct.unpack("!i", datagram[4:8]))[0]
    			keyNodeData = struct.unpack("%dB" % keyNodeLen, datagram[8:8+keyNodeLen])
    			self.keyNodes[position] = bytearray(keyNodeData)
    			self.GroupDHComputation()
    		else:
    			datagram = self.httpclient.sync_keynodes(self.userID)
    			self.handleSyncKeyNodes(datagram)
    
    def GroupDHComputation(self):
    	# Doing DH group key construction
    	position = 0
    	currentKeyNodeNumber = 0
    	firstKeynode = True
    	self.uidSet.sort()
    	for x in self.uidSet:
    		if x == self.userID:
    			break
    		else:
    			position += 1
    	
    	# If position 1 or 0
    	# print "position = %d" % position
    	if position < 2:
    		# If 1 set keynode 1 to be pubkey 0 and vice versa
    		currentKeyNodeNumber = 2
    		self.keyNodes[1] = bytearray(self.dhpubkeySet[self.uidSet[1-position]])
    	else:
    		# Check if you have the keynode corresponding to you position.
    		try:
    			elem = self.keyNodes[position]
    		except KeyError:
    			datagram = self.httpclient.sync_keynodes(self.userID)
    			self.handleSyncKeyNodes(datagram)
    			return
    		currentKeyNodeNumber = position+1
    	
    	currentKeynode = DiffieHellman()
    	sharedKey = None
    	
    	while currentKeyNodeNumber <= len(self.uidSet):
    		#For the first keynode that you generate use your private key and keynode as public key
    		if firstKeynode:
    			pubKey = int(binascii.hexlify(self.keyNodes[currentKeyNodeNumber-1]), 16)
    			sharedKey = self.dhkey.genSecret(self.dhkey.privateKey, pubKey)
    			firstKeynode = False
    		else:
    			pubKey = int(binascii.hexlify(bytearray(self.dhpubkeySet[self.uidSet[currentKeyNodeNumber-1]])), 16)
    			sharedKey = self.dhkey.genSecret(currentKeynode.privateKey, pubKey)
    		
    		# Storing generated shared key in DH struct for key node, currentKeynode->priv_key = sharedKey
    		currentKeynode.privateKey = sharedKey
    		
    		# If position 1 or 0
    		if position < 2 and currentKeyNodeNumber < len(self.uidSet):
    			# Send exponentiated keynode to server
    			expKeyNode = pow(currentKeynode.generator, currentKeynode.privateKey, currentKeynode.prime)
    			hex_string = hex(expKeyNode)
    			expKeyNodeRaw = hex_string[2:-1].decode("hex")
    			datagram = self.httpclient.sync_requestkeynodes(self.userID, 
    			                                                self.uidSet[currentKeyNodeNumber],
    			                                                expKeyNodeRaw)
    		
    		currentKeyNodeNumber += 1
    	
    	# compute group DH key
    	hex_string = hex(sharedKey).strip()
    	#print "sharedKey: %s" % hex_string[2:-1]
    	self.groupkey = hex_string[2:-1].decode("hex")
    	del sharedKey
    	self.SyncMatch()
    
    def SyncMatch(self):
    	self.match_nonce = CryptoEngine.aes256_cbc_encryption(self.match_nonce, self.groupkey)
    	numUsers_Recv = 1
    	del self.uidSet[:]
    	self.uidSet.insert(0, self.userID)
    	retry = 0
    	while (numUsers_Recv < self.num_users):
    		datagram = self.httpclient.sync_match(self.userID,
    		                                      self.uidSet,
    		                                      self.match_nonce)
    		count = (struct.unpack("!i", datagram[0:4]))[0]
    		delta_count = (struct.unpack("!i", datagram[4:8]))[0]
    		# Collect all data commitments Ci from other users
    		if delta_count > 0:
    			offset = 8
    			for i in range(delta_count):
    				uid = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				self.uidSet.append(uid)
    				offset += 4
    				total_len = (struct.unpack("!i", datagram[offset:offset+4]))[0]
    				offset += 4
    				keyNonce = struct.unpack("%dB" % total_len, datagram[offset:offset+total_len])
    				keyNonce = CryptoEngine.aes256_cbc_decryption(keyNonce, self.groupkey)
    				nh = CryptoEngine.sha3_digest(bytes(keyNonce))
    				meh = self.matchExtraHashSet[uid]
    				if nh == bytearray(meh):
    					self.matchNonceSet[uid] = keyNonce
    				else:
    					print "An error occurred during commitment verification."
    					quit()
    				offset += total_len
    				numUsers_Recv += 1
    		retry += 1
    		time.sleep(retry)
    		if retry >= 10:
    			print "Error: reached maximum retries"
    			quit()
    
    
    def ObtainGatherData(self):
    	# decrypted the final data
    	_decrypted = {}
    	for x in self.uidSet:
    		if x == self.userID: continue
    		individualData = CryptoEngine.aes256_cbc_decryption(self.receivedcipherSet[x], self.matchNonceSet[x])
    		_decrypted[x] = individualData
    	return _decrypted
    
    def __del__(self):
    	
    	self.httpclient.close()
    	del self.httpclient
    	
    	# predefined data structures
    	del self.match_nonce
    	del self.wrong_nonce
    	del self.match_extrahash
    	del self.match_hash
    	del self.encrypted_data
    	del self.protocol_commitment
    	del self.dhkey
    	del self.data_commitment
    	del self.userID
    	del self.groupkey
    	
    	del self.uidSet
    	del self.dataCommitmentSet
    	del self.protoCommitmentSet
    	del self.dhpubkeySet
    	del self.receivedcipherSet
    	del self.matchExtraHashSet
    	del self.wrongHashSet
    	del self.matchHashSet
    	del self.keyNodes
    	del self.matchNonceSet
    	
    	# load dictionary files
    	del self.odd_array
    	del self.even_array

