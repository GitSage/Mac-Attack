from macattack import continue_sha1
import hashlib

key = 'key'
message = 'message'
mac = hashlib.sha1(key+message).hexdigest()

append = 'extend'

extended_message, extended_mac = continue_sha1(mac, message, append, len(key))

result_mac = hashlib.sha1(key+extended_message).hexdigest()
if result_mac == extended_mac:
    print "Success."
else:
    print "Failure. Extended mac: %s, expected mac: %s" % (extended_mac, result_mac)

