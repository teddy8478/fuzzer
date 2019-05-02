#from scapy.all import *
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
		msgs = []
		for num, packets in s_dict.items():	#for each stream
			if hasattr(packets[0], 'ip'):
				src = packets[0].ip.src
			elif hasattr(packets[0], 'ipv6'):
				src = packets[0].ipv6.src
			req = b''
			resp = b''
			cur_ip = src
			for packet in packets:
				if not hasattr(packet.tcp, 'payload'):
					continue
				raw = str(packet.tcp.payload).replace(':', '')
				if hasattr(packet, 'ip'):
					if packet.ip.src == src:
						req += binascii.a2b_hex(raw)	
					else:
						resp += binascii.a2b_hex(raw)
				elif hasattr(packet, 'ipv6'):
					if packet.ipv6.src == src:
						req += binascii.a2b_hex(raw)	
					else:
						resp += binascii.a2b_hex(raw)
			#case by case
			if floder == 'log/pulg':
				pass
			elif floder == 'log/tplink':
				req = decrypt(req)
				resp = decrypt(resp)
			#pdb.set_trace()
			
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

def decrypt(string):	#tplink hs110
	key = 171
	result = ""
	for i in string[4:]:
		a = key ^ i
		key = i
		result += chr(a)
	return result.encode()

class msg:
	def __init__(self, index, req, resp, f):
		self.index = index
		self.req = req
		self.resp = resp
		self.file = f		
		self.group = -1
		self.keys = []
		self.parts, self.deli_order = parse(req)
		self.resp_parts, self.resp_deli = parse(resp)
		self.all_seg = self.parts + self.resp_parts
		

	def __repr__(self):
		re = 'File ' + str(self.file) + '\nRequest:' + str(self.req) + '\n'
		return re

def parse(raw):
	parts = []
	first_sym = b' |\r|\n'
	symbols = b' |:|/|&|=|\r|\n|,|\?|\"|<|>|#|\[|\]|\{|\}'
	non_base64 = b' |:|&|=|\r|\n|,|\?|\"|<|>|#|\[|\]|\{|\}'
	deli_order = raw
	seg = re.split(first_sym, raw)
	for s in seg:
		if len(s) > 100:
			splits = re.split(symbols, s)
			deli = s
			for sp in splits:
				deli = deli.replace(sp, b'', 1)
			match = re.findall(r'[\/|\+]+', deli.decode('utf-8'))
			if len(match) == 0 or len(max(match)) / len(deli) > 0.7:
				parts += re.split(non_base64, s)
			else:
				parts += re.split(symbols, s)
		else:
			parts += re.split(symbols, s)
	for s in parts:
		deli_order = deli_order.replace(s, b'', 1)

	return parts, deli_order
