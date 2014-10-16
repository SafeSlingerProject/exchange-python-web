from safeslinger import SafeSlingerExchange

exchange_data = None
proto = SafeSlingerExchange()

while True:
    try:
        exchange_data = str(raw_input("Enter the string you want to exchange with people in the group: "))
        if len(exchange_data) > 0: 
        	break
        else:
        	print 'The exchange is missing required data.'
    except Exception:
    	print 'The exchange is missing required data.'
    
print 'My Secretto Exchange: %s' % exchange_data	

# select group size
proto.SelecGroupSize()
# start exchange
proto.BeginExchange(exchange_data.encode('utf-8'))
# assign user ID obtained from the server
proto.AssignUser()
# compare and enter the lowest number
proto.SelectLowestNumber()
# compute and display 3-words phrases
proto.Compute3Wordphrases()
# perform 3-words phrases verifications
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
