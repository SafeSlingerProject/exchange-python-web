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

    def setAddress(addr):
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
    
    def doPost(self,name,packdata):
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
 	
 	# assignUser: char request[4 + HASHLEN].
 	# 4b: htonl(version);
 	# 32b: data_commitment
    def assignUser(self, data_commitment):
        if not self.connected:
            return None
        pack = struct.pack('!i%dB'%len(data_commitment), self.version , *data_commitment)
        response = self.doPost('/assignUser', pack)
        return response
 	
 	# sendMinID: char request[4 + 4 + 4 + 4 + 4 + HASHLEN];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(minID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: data_commitment
    def sendMinID(self,userID,minID,allUsers,data_commitment):
        if not self.connected:
            return None
        
        num_item = 4+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, minID, len(allUsers), *allUsers)
        pack += struct.pack('%dB'% len(data_commitment), *data_commitment)
        response = self.doPost('/syncUsers',pack)
        return response
    
    # SyncData: char request[4 + 4 + 4 + 4 + HASHLEN + (int)[encrypted_data length] + DHPubKeySize];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: protocol_commitment
 	# various bytes: dh_pubkey
 	# various bytes: encrypted_data
    def SyncData(self,userID,protocol_commitment,dh_pubkey,allUsers,encrypted_data):
        if not self.connected:
            return None
            
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, len(allUsers), *allUsers)
        bArray = bytearray(protocol_commitment)
        bArray.extend(dh_pubkey)
        bArray.extend(encrypted_data)
        pack += struct.pack('%dB' %len(bArray), *bArray)
        response = self.doPost('/syncData',pack)
        
        return response
    
    # SyncSignatures: char request[4 + 4 + 4 + 4 + HASHLEN * 2];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: match_extrahash (match) or match_hash (non match)
 	# 32b: wrong_hash (match) or wrong_nonce (non match)
    def SyncSignatures(self,userID,allUsers,hash1,hash2):
        if not self.connected:
            return None
        
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, len(allUsers), *allUsers)
        bArray = bytearray(hash1)
        bArray.extend(hash2)
        pack += struct.pack('%dB' %len(bArray), *bArray)
        response = self.doPost('/syncSignatures',pack)
        return response
    
    # SyncKeyNodes: char keynodeRequest[4 + 4];
 	# 4b: htonl(version);
 	# 4b: htonl(userID);
    def SyncKeyNodes(self,userID):
        if not self.connected:
            return None
        pack = struct.pack('!2i', self.version, userID)
        response = self.doPost('/syncKeyNodes',pack)
        return response
    
    # SyncKeyNodesForDHTree: char keynodeRequest[4 + DH_size];
    # 4b: htonl(version);
    # 4b: htonl([userID intValue]);
    # 4b: htonl([[userIDs objectAtIndex:currentKeyNodeNumber] intValue]);
    # 4b: keynodeRequest[3] = htonl(DH_size(diffieHellmanKeys));
    # BN_bn2bin(expKeyNode, (unsigned char*)(&keynodeRequest[4]));
    def SyncRequestKeyNodes(self,userID,requestID,dhSize,expKeyNode):
        if not self.connected:
            return None
        pack = struct.pack('!4i', self.version, userID, requestID, dhSize)
        pack += struct.pack('%dB' %len(expKeyNode), *expKeyNode)
        response = self.doPost('/syncKeyNodes',pack)
        return response
    
    # SyncMatch: char request[4 + 4 + 4 + 4 + (int)[match_nonce length]];
 	# 4b: htonl(version)
 	# 4b: htonl(userID)
 	# 4b: htonl(# of users);
 	# 4b * x: htonl(userIDs);
 	# 32b: match_nonce
    def SyncMatch(self,userID,allUsers,match_nonce):
        if not self.connected:
            return None
        
        num_item = 3+len(allUsers)
        pack = struct.pack('!%di'% num_item, self.version, userID, len(allUsers), *allUsers)
        bArray = bytearray(match_nonce)
        pack += struct.pack('%dB' %len(bArray), *bArray)
        response = self.doPost('/syncMatch',pack)
        
        return response
