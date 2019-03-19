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
		raw = []
		src = packets[0][IP].src
		dst = packets[0][IP].dst
		pre_src = dst
		for p in packets:
			if p[IP].src == pre_src:
				raw[-1] += str(p[Raw])[2:-1]
			else:
				raw.append(str(p[Raw])[2:-1])
			pre_src = p[IP].src
		
		
		i=0
		num = len(raw)
		for i in range(int(num/2)): #create resp/req pair
			req_raw = raw[i*2]
			resp_raw = raw[i*2 + 1]
			
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
