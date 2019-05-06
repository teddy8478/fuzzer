from os import listdir
import re
import pdb
import math
import pyshark
import collections
import binascii
import gzip

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
				dst = packets[0].ip.dst
			elif hasattr(packets[0], 'ipv6'):
				src = packets[0].ipv6.src
				dst = packets[0].ipv6.dst
			srcport = packets[0].tcp.srcport
			dstport = packets[0].tcp.dstport

			req = r''
			resp = r''
			cur_ip = src
			req += packets[0].sniff_timestamp + ' T ' + src + ':' + srcport + ' ' + dst + ':' + dstport + ' '
			resp += packets[0].sniff_timestamp + ' T ' + dst + ':' + dstport + ' ' + src + ':' + srcport + ' '
			for packet in packets:
				if not hasattr(packet.tcp, 'payload'):
					continue
				raw = str(packet.tcp.payload).replace(':', '')
				if hasattr(packet, 'ip'):
					if packet.ip.src == src:
						req += binascii.a2b_hex(raw).decode('utf-8', 'ignore')	
					else:
						resp += binascii.a2b_hex(raw).decode('utf-8', 'ignore')
				elif hasattr(packet, 'ipv6'):
					if packet.ipv6.src == src:
						req += binascii.a2b_hex(raw).decode('utf-8', 'ignore')	
					else:
						resp += binascii.a2b_hex(raw).decode('utf-8', 'ignore')

			'''
			req = decrypt(req)
			resp = decrypt(resp)
			pdb.set_trace()
			'''
			ret.append(req)
			ret.append(resp)
			index += 1
		f_num += 1
	return ret

msgs = read_pyshark('log/plug')
f = gzip.open("plug.drk", "wb")
write_list = []
for m in msgs:
	m = m.replace('\r', '%0d')
	m = m.replace('\n', '%0a').encode()
	m += b'\n'
	#pdb.set_trace()
	write_list.append(m)
f.writelines(write_list)
f.close()


