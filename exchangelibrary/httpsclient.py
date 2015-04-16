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

import httplib, urllib, ssl
import struct, socket
from ctypes import *

class HTTPClient:

    def __init__(self, address="", version = 1 << 24 | 8 << 16):
        self.address = address
        print 'Connect to Server: %s' % self.address
        self.connection = None
        self.connected = False
        self.version = version
        if address != "":
            self.connect()

    def set_address(addr):
        self.address(addr)

    def connect(self):
        if self.address == "":
            return -1
        #context = ssl.create_default_context(Purpose.SERVER_AUTH)
        self.connection = httplib.HTTPSConnection(self.address, 443, None)
        self.connected = True
        return 0

    def close(self):
        self.connection.close()
        self.conected = False
    
    def do_post(self,name,packdata):
        if not self.connected:
            return None
        headers = {"Content-Type": "application/octet-stream"}
        self.connection.request("POST", name, packdata, headers)
        response = self.connection.getresponse()
        #print response.status, response.reason
        if response.status == 200:
        	data = response.read()
        	code = (struct.unpack("!i", data[0:4]))[0]
        	if code == 0:
        		raise Exception('Server Error', str(struct.unpack("s", ret[4:])))
        	else:
        		return data[4:]
        else:
        	print "Network error: return code %d, reason = %s" % (response.status, response.reason)
 	
 	# assign_user: char request[4 + HASHLEN];
 	# 4b: htonl(version);
 	# 32b: data_commitment
    def assign_user(self, data_commitment):
        if not self.connected:
            return None
        pack = struct.pack('!i%dB' % len(data_commitment), 
                           self.version, *bytearray(data_commitment))
        response = self.do_post('/assignUser', pack)
        return response
 	
 	# send_minid: char request[4 + 4 + 4 + 4 + 4 + HASHLEN];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(minID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: data_commitment
    def send_minid(self, userID, minID, allUsers, data_commitment):
        if not self.connected:
            return None
        
        num_item = 4+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, minID, len(allUsers), *allUsers)
        pack += struct.pack('%dB'% len(data_commitment), *bytearray(data_commitment))
        response = self.do_post('/syncUsers',pack)
        return response
    
    # sync_data: char request[4 + 4 + 4 + 4 + HASHLEN + (int)[encrypted_data length] + DHPubKeySize];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: protocol_commitment
 	# various bytes: dh_pubkey
 	# various bytes: encrypted_data
    def sync_data(self,userID,allUsers,protocol_commitment,dh_pubkey,encrypted_data):
        if not self.connected:
            return None
            
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, len(allUsers), *allUsers)
        blen = len(protocol_commitment)+len(dh_pubkey)+len(encrypted_data)
        pack += struct.pack('%dB' %blen, *bytearray(protocol_commitment + dh_pubkey + encrypted_data))
        response = self.do_post('/syncData',pack)
        
        return response
    
    # sync_signatures: char request[4 + 4 + 4 + 4 + HASHLEN * 2];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: match_extrahash (match) or match_hash (non match)
 	# 32b: wrong_hash (match) or wrong_nonce (non match)
    def sync_signatures(self,userID,allUsers,hash1,hash2):
        if not self.connected:
            return None
        
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, len(allUsers), *allUsers)
        blen = len(hash1)+len(hash2)
        pack += struct.pack('%dB' % blen, *bytearray(hash1 + hash2))
        response = self.do_post('/syncSignatures',pack)
        return response
    
    # sync_keynodes: char keynodeRequest[4 + 4];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
    def sync_keynodes(self,userID):
        if not self.connected:
            return None
        pack = struct.pack('!2i', self.version, userID)
        response = self.do_post('/syncKeyNodes',pack)
        return response
    
    # sync_requestkeynodes: char keynodeRequest[4 + DH_size];
    # 4b: htonl(version);
    # 4b: htonl([userID intValue]);
    # 4b: htonl([[userIDs objectAtIndex:currentKeyNodeNumber] intValue]);
    # 4b: keynodeRequest[3] = htonl(DH_size(diffieHellmanKeys));
    # BN_bn2bin(expKeyNode, (unsigned char*)(&keynodeRequest[4]));
    def sync_requestkeynodes(self,userID,requestID,expKeyNode):
        if not self.connected:
            return None
        dhsize = len(expKeyNode)
        pack = struct.pack('!4i', self.version, userID, requestID, dhSize)
        pack += struct.pack('%dB' % len(expKeyNode), *bytearray(expKeyNode))
        response = self.do_post('/syncKeyNodes',pack)
        return response
    
    # sync_match: char request[4 + 4 + 4 + 4 + (int)[match_nonce length]];
 	# 4b: htonl(version)
 	# 4b: htonl(userID)
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: match_nonce
    def sync_match(self,userID,allUsers,match_nonce):
        if not self.connected:
            return None
        
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di' % num_item, self.version, userID, len(allUsers), *allUsers)
        pack += struct.pack('%dB' % len(match_nonce), *bytearray(match_nonce))
        response = self.do_post('/syncMatch',pack)
        
        return response
