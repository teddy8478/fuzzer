from scapy.all import *
from os import listdir
import re
import pdb

def read_pcap(floder):
	ret = []
	cnt = 0
	index = 0
	for filename in listdir(floder):
		packets = rdpcap(str(floder) + '/' + str(filename))
		i=0
		num = len(packets)
		for i in range(int(num/2)): #create resp/req pair
			req_raw = str(packets[i*2][Raw])
			req_raw = req_raw[2:-1] #remove unicode u'XXXX'
			resp_raw = str(packets[i*2+1][Raw])
			resp_raw = resp_raw[2:-1]
			req_raw = req_raw.replace('\\r', '\r')
			req_raw = req_raw.replace('\\n', '\n')
			resp_raw = resp_raw.replace('\\r', '\r')
			resp_raw = resp_raw.replace('\\n', '\n')
			ret.append(msg(index, req_raw, resp_raw, cnt))
			index += 1
		cnt += 1
	return ret

class msg:
	def __init__(self, index, req, resp, f):
		self.index = index
		self.req = req
		self.resp = resp
		self.file = f
		self.parts = re.split(' |:|/|&|=|\r|\n|,|\?', req)
		self.resp_parts = re.split(' |:|/|&|=|\r|\n|,|\?', resp)
		self.group = -1
		self.keys = []
		self.deli_order = req
		for p in self.parts:
			self.deli_order = self.deli_order.replace(p, '', 1)

	def __repr__(self):
		re = 'File ' + str(self.file) + '\nRequest:' + self.req + '\n'
		return re
