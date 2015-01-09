# The MIT License (MIT)
#
# Copyright (c) 2010-2014 Carnegie Mellon University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from safeslinger import SafeSlingerExchange

exchange_data = None
proto = SafeSlingerExchange()

while True:
    try:
        exchange_data = str(raw_input('Enter a Secret you want to exchange with people in the group: '))
        if len(exchange_data) > 0: 
            break
        else:
            print 'The exchange is missing required data.'
    except Exception:
    	print 'The exchange is missing required data.'
    
print 'My Secret to exchange: %s' % exchange_data	

# select group size
proto.SelecGroupSize()
# start exchange
proto.BeginExchange(exchange_data.encode('utf-8'))
# assign user ID obtained from the server
proto.AssignUser()
# compare and enter the lowest number
proto.SelectLowestNumber()
# compute and display 3-word phrases
proto.Compute3Wordphrases()
# perform 3-word phrase verifications
ret = proto.PhrasesVerification()

if ret == True: 
	proto.GroupDHComputation()
	_decrypted = proto.ObtainGatherData()
	print "\n\n"
	print "---------------Exchange Result---------------"
	for x in _decrypted.keys():
		print "User (%d)'s data: %s" % (x, _decrypted[x])
	print "---------------------------------------------"
del proto

