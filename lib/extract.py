from scapy.all import *
from os import listdir
import re
import pdb
import math
import pyshark
import collections
import binascii

def read_pyshark(floder):
	ret = []
	index = 0
	f_num = 0
	for filename in listdir(floder):
		name = str(floder) + '/' + str(filename)
		#cap = pyshark.FileCapture(name, display_filter='tcp.stream eq %d' % 1)
		cap = pyshark.FileCapture(name)
		s_dict = {}
		for c in cap:
			if int(c.tcp.stream) in s_dict.keys():
				s_dict[int(c.tcp.stream)].append(c)
			else:
				s_dict[int(c.tcp.stream)] = [c]
		s_dict = collections.OrderedDict(sorted(s_dict.items()))
		
		for num, packets in s_dict.items():
			src = packets[0].ip.src
			req = b''
			resp = b''
			for packet in packets:
				raw = str(packet.tcp.payload).replace(':', '')
				if packet.ip.src == src:
					req += binascii.a2b_hex(raw)	
				else:
					resp += binascii.a2b_hex(raw)
			ret.append(msg(index, req, resp, f_num))
			index += 1
		f_num += 1
	return ret

def read_pcap_test(f):
	ret = []
	index = 0
	packets = rdpcap(f)
	for p in packets:
		try:
			req_raw = str(p[Raw])[2: -1]
			ret.append(msg(index, req_raw, '', 0))
			index += 1
		except:
			pass

	return ret

def entropy(input_s):
	en = 0.0
	input_set = set(list(input_s))
	for s in input_set:
		freq = input_s.count(s) / len(input_s)
		en += freq * math.log(freq, 2)
	return -en

class msg:
	def __init__(self, index, req, resp, f):
		self.index = index
		self.req = req
		self.resp = resp
		self.file = f
		self.parts = []
		self.resp_parts = []
		self.group = -1
		self.keys = []
		self.deli_order = req
		
		symbols = b' |:|/|&|=|\r|\n|,|\?|\"|<|>|#|-'
		splits = re.split(symbols, req)
		deli = req
		for s in splits:
			deli = deli.replace(s, b'', 1)
		th = 3.5	#entropy threshold
		i = 0
		while i < len(splits):
			if entropy(splits[i]) >= th:
				self.parts.append(splits[i])
				while True:
					if entropy(splits[i+1]) >= th:
						self.parts[-1] += chr(deli[i]).encode() + splits[i+1]
						i += 2
					elif entropy(splits[i+2]) >= th:
						self.parts[-1] += chr(deli[i]).encode() + splits[i+1] + chr(deli[i+1]).encode() + splits[i+2]
						i += 3
					elif entropy(splits[i+3]) >= th:
						self.parts[-1] += chr(deli[i]).encode() + splits[i+1] + chr(deli[i+1]).encode() + splits[i+2]+ chr(deli[i+2]).encode() + splits[i+3]
						i += 4
					else:
						#pdb.set_trace()
						i += 1			
						break
			else:
				self.parts.append(splits[i])
				i += 1

		for s in self.parts:
			self.deli_order = self.deli_order.replace(s, b'', 1)

		

	def __repr__(self):
		re = 'File ' + str(self.file) + '\nRequest:' + str(self.req) + '\n'
		return re
