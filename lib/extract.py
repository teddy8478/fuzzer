from scapy.all import *
from os import listdir
import re
import pdb
import pyshark

def read_pyshark(floder):
	ret = []
	index = 0
	f_num = 0
	for filename in listdir(floder):
		name = str(floder) + '/' + str(filename)
		#cap = pyshark.FileCapture(name, display_filter='tcp.stream eq %d' % 1)
		cap = pyshark.FileCapture(name)
		s_num = []
		for c in cap:
			if not c.tcp.stream in s_num:
				s_num.append(c.tcp.stream)
		for num in s_num:
			cur_s = [c for c in cap if c.tcp.stream == num]
			src = cur_s[0].ip.src
			req = ''
			resp = ''
			for packet in cur_s:
				raw = str(packet.tcp.payload).replace(':', '')
				if packet.ip.src == src:
					req += bytearray.fromhex(raw).decode()	
				else:
					resp += bytearray.fromhex(raw).decode()
			ret.append(msg(index, req, resp, f_num))
			index += 1
		f_num += 1
	return ret

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
