import socket
import sys
import re
import os
import pdb
import time
import lib.extract as extract
import lib.state as state
from struct import pack
from binascii import unhexlify
from signal import signal, SIGPIPE, SIG_DFL

def tplink_fuzz(msgs, conn):
	#host = '192.168.0.1'
	host = '192.168.200.6'
	port = 9999
	msg_num = len(msgs)
	#signal(SIGPIPE, SIG_DFL)
	#s.settimeout(0.0)
	for m in msgs:
		data = b''
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			s.send(encrypt(m))
				
			#pdb.set_trace()
			seg = s.recv(1024)
			#sys.stdout.write(extract.decrypt(seg).decode() + '\n')
			if not seg:
				pass
			else:
				data = extract.decrypt(seg)
		except socket.error as e:
			sys.stdout.write(m.decode())
			sys.stdout.write(e)
		s.close()
	return data

def tcp_fuzz(msgs, conn):
	host = conn[0]	
	port = conn[1]
	msg_num = len(msgs)
	open_p = []
	pre_p = port
	time.sleep(1)
	for p in range(49153, 49157):	#port scanning
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if c.connect_ex((host, p)) == 0:
			open_p.append(p)
		c.close()

	port = open_p[0]
	report = []
	i = 0
	while i < msg_num:	
		while True:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))
				#print('current port: ' + str(port))
				break
			except Exception as e:
				s.close()
				print(e)
				open_p = []
				pre_p = port
				time.sleep(1)
				for p in range(49153, 49157):	#port scanning
					c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if c.connect_ex((host, p)) == 0:
						open_p.append(p)
				c.close()
				print(open_p)				
				if port == open_p[0]:
					port = open_p[-1]
				else:
					port = open_p[0]
				print('using port: ' + str(port))
				
		try:					
			s.settimeout(3)
			data = ''
			m = http(msgs[i])		
			s.send(m)					
			while True:			
				seg = s.recv(1024)			
				if not seg:
					break
				else:
					data += seg.decode("utf-8")	
			i += 1					
		except Exception as e: 
			print(e)
			#print(cnt)
			#pdb.set_trace()
			if len(open_p) == 1:
				open_p = []
				for p in range(49153, 49157):	#port scanning
					c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if c.connect_ex((host, p)) == 0:
						open_p.append(p)
				c.close()
				port = open_p[0]

			if port == open_p[0]:				
				port = open_p[-1]
			else:
				print('msg: ' + str(m))
				err = {}
				err['error'] =  e
				err['msg'] = m
				report.append(err)
				i += 1

				open_p = []
				for p in range(49153, 49157):	#port scanning
					c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if c.connect_ex((host, p)) == 0:
						open_p.append(p)
				c.close()
				port = open_p[0]
		s.close()				
			#pdb.set_trace()		
	print(report)
	return data

def http(m):
	field = m.split(b"\r\n")
	content_len = len(field[-1])
	
	for i in range(len(field)):
		if field[i].startswith(b'Content-Length'):
			field[i] = field[i][0:15]
			field[i] += str(content_len).encode()			
			break
	m = b'\r\n'.join(field)
	
	return m

def mutate(msg, rule):
	g = msg.group
	index = msg.index
	fuzz_list = []
	values = []
	orig = [m for m in g.msgs if m.index == index][0]
	#pdb.set_trace()
	part = orig.parts
	deli = g.deli_order + [32]
	if set(g.fields) == {None}:
		return [orig.req]
	#read patterns
	with open("ptn/int", "r", encoding="utf-8") as f:
	    int_ptn = []
	    for line in f:
	        int_ptn.append(line[:-1])
	with open("ptn/float", "r", encoding="utf-8") as f:
	    float_ptn = []
	    for line in f:
	        float_ptn.append(line[:-1])
	with open("ptn/string", "r", encoding="utf-8") as f:
	    string_ptn = []
	    for line in f:
	        string_ptn.append(line[:-1])

	for cur in range(len(part)):
		if g.fields[cur] == None or g.fields[cur] =='':
			continue
			
		if g.fields[cur] == 'int':
			ptn = int_ptn
		elif g.fields[cur] == 'float':
			ptn = float_ptn
		elif g.fields[cur] == 'string':
			ptn = string_ptn
		for p in ptn:
			flow = b''
			for i in range(len(part)):
				if i in rule.keys():
					flow += rule[i] + chr(deli[i]).encode()
					continue
				if i == cur:
					flow += p.encode() + chr(deli[i]).encode()
				else:
					flow += part[i] + chr(deli[i]).encode()
			fuzz_list.append(flow)

	return fuzz_list

def start(root, end, s_list, trace, conn, rules):
	
	for e in end:
		cur = root
		cur_tr = s_list[e].trace[0]
		print('Trace ' + str([m.group.index for m in trace[cur_tr]]))
		pre_resp = [None] * len(rules)
		for m in trace[cur_tr]:
			g = m.group.index
			if g not in cur.remain:
				print('Replay group ' + str(m.group.index))
				#pdb.set_trace()
				if sys.argv[1] == 'tplink':
					pre_resp[g] = tplink_fuzz([m.req], conn)
				elif sys.argv[1] == 'plug':
					pre_resp[g] = tcp_fuzz(m, conn)
				cur = cur.trans[g]
				continue
				
			cur_r = dict()
			for r in rules[g]:
				part, deli = extract.parse(pre_resp[r[1]])
				cur_r[r[0]] = part[r[2]]

			fuzz_msg = mutate(m, cur_r)
			#print('Fuzzing state ' + str(cur.index) + ', group ' + str(g))
			print('Fuzzing state %d, group %d, %d test cases...' % (cur.index, g, len(fuzz_msg)))
			resp = b''			
			for f in fuzz_msg:
				if sys.argv[1] == 'tplink':
					tplink_fuzz([f], conn)
				elif sys.argv[1] == 'plug':
					tcp_fuzz(f, conn)
			if sys.argv[1] == 'tplink':
				pre_resp[g] = tplink_fuzz([m.req], conn)
			elif sys.argv[1] == 'plug':
				pre_resp[g] = tcp_fuzz(m, conn)
			cur.remain.remove(g)
			cur = cur.trans[g]
			if cur.index == 1:
				break
		print('Restart the device\n')	

def encrypt(string):	#tplink
	key = 171
	result = pack('>I', len(string))
	for i in string:
		a = key ^ i
		key = a
		hex_v = hex(a)[2:]
		if len(hex_v) == 1:
			hex_v = '0' + hex_v
		result += unhexlify(hex_v)
	#pdb.set_trace()
	return result

