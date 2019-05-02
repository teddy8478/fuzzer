import pdb
from struct import pack
from binascii import unhexlify

def decrypt(string):	#tplink hs110
	key = 171
	result = ""
	for i in string[4:]:
		a = key ^ i
		key = i
		result += chr(a)
	return result.encode()

def encrypt(string):	#tplink
	key = 171
	#pdb.set_trace()
	#result = pack('>I', len(string))
	result = b'\x00\x00\x00\x00'
	for i in string:
		a = key ^ i
		key = a
		result += unhexlify(hex(a)[2:])
	#pdb.set_trace()
	return result

data = b'{"context":{"source":"46a4d58b-6279-432c-ae23-e115c2db8354"},"schedule":{"get_rules":{}}}'
pdb.set_trace()
en = encrypt(data)
print(decrypt(en))



