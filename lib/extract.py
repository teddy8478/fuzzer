from scapy.all import *
from os import listdir
import re

def read_pcap(floder):
	ret = []
	cnt = 0
	for filename in listdir(floder):
		packets = rdpcap(str(floder) + '/' + str(filename))
		i=0
		num = len(packets)
		for i in range(int(num/2)): #create resp/req pair
			req_raw = str(packets[i*2][Raw])
			req_raw = req_raw[2:-1] #remove unicode u'XXXX'
			resp_raw = str(packets[i*2+1][Raw])
			resp_raw = resp_raw[2:-1]
			ret.append(msg(req_raw, resp_raw, cnt))
		cnt += 1
	return ret

class msg:
	def __init__(self, req, resp, f):
		self.req = req
		self.resp = resp
		self.file = f
		self.parts = re.split(' |:|/|&|=|\r|\n|,', req)
		self.group = -1
	def __repr__(self):
		re = 'File ' + str(self.file) + '\nRequest:' + self.req + '\nResponse: ' + self.resp + '\n'
		return re
