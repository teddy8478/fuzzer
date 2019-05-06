from gzip import GzipFile
import urllib
import pdb
#with GzipFile('plug.drk', "rb") as g:
with GzipFile('../pulsar/models/itunes-xbmc/itunes-xbmc.drk', "rb") as g:
	messages = [] 
	for l in g:
		print(l)
		pdb.set_trace()
		messages.append(urllib.unquote(l.rstrip("\r\n").split(" ", 4)[-1]))
	g.close()
	print(len(messages))
 
