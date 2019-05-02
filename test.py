import pdb
from struct import pack
from binascii import unhexlify
from lib.extract import *
from lib.fuzz import *

data = b'{"context":{"source":"46a4d58b-6279-432c-ae23-e115c2db8354"},"schedule":{"get_rules":{}}}'
pdb.set_trace()
en = encrypt(data)
print(decrypt(en))



