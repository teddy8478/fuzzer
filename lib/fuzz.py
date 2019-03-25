import socket
import re
import os
import pdb
import time

def tcp_fuzz(msgs):
	host = '192.168.200.5'
	port = 49153
	
	cnt = 1
	for m in msgs:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, port))
		#print(cnt)
		cnt += 1
		data = ''
		m = http(m)
		s.send(m.encode())
		#print(m.req)			
		while True:			
			seg = s.recv(1024)			
			if not seg:
				break
			else:
				data += seg.decode("utf-8")				
		#print('Received', repr(data))
		s.close()

	return data

def http(m):
	field = m.split(b"\r\n")
	content_len = len(field[-1])
	
	for i in range(len(field)):
		if field[i].startswith('Content-Length'):
			field[i] = field[i][0:15]
			field[i] += str(content_len).encode()			
			break
	m = b'\r\n'.join(field)
	
	return m

def mutate(msg):
	g = msg.group
	index = msg.index
	fuzz_list = []
	values = []
	orig = [m for m in g.msgs if m.index == index][0]
	#pdb.set_trace()
	part = orig.parts
	deli = g.deli_order + ['']
	if set(g.fields) == {None}:
		return [orig.req]
	#read patterns
	with open("ptn/int", "r") as f:
	    int_ptn = []
	    for line in f:
	        int_ptn.append(line[:-1])
	with open("ptn/float", "r") as f:
	    float_ptn = []
	    for line in f:
	        float_ptn.append(line[:-1])
	with open("ptn/string", "r") as f:
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
			flow = ''
			for i in range(len(part)):
				if i == cur:
					flow += p + deli[i]
				else:
					flow += part[i] + deli[i]
			fuzz_list.append(flow)

	return fuzz_list

def start(root, end, s_list, msgs):
	trace = []
	for i in range(msgs[-1].file + 1):
		trace.append([m for m in msgs if m.file == i])
	
	for e in end:
		cur = root
		cur_tr = s_list[e].trace[0]
		print('Trace ' + str([m.group.index for m in trace[cur_tr]]))
		for m in trace[cur_tr]:	
			g = m.group.index
			if cur.fuzzed:
				print('Replay group ' + str(m.group.index))
				#tcp_fuzz(m)
				cur = cur.trans[g]
				continue
			fuzz_msg = mutate(m)
			print('Fuzzing state ' + str(cur.index) + ', group ' + str(g))
			'''
			for f in fuzz_msg:
				resp = tcp_fuzz(f)
			'''
			cur.fuzzed = True
			cur = cur.trans[g]
			if cur.index == 1:
				break
		print('Restart the device\n')	
