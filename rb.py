from gzip import GzipFile
import urllib
import pdb
import sys


input_dir = sys.argv[1]
with GzipFile(input_dir + '.drk', "rb") as g:
#with GzipFile('../pulsar/models/itunes-xbmc/itunes-xbmc.drk', "rb") as g:
	messages = [] 
	for l in g:
		print(l)
		#pdb.set_trace()
		messages.append(urllib.unquote(l.rstrip("\r\n").split(" ", 4)[-1]))
	g.close()
	print(len(messages))
 
