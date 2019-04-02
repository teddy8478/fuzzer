import socket
import re
import os
import pdb
import time

def tcp_fuzz(msgs, host, port):
	#host = '192.168.200.5'	
	cnt = 0
	report = []
	#port = 49154
	for m in msgs[cnt:]:
				
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((host, port))		
			s.settimeout(5)
			data = ''
			m = http(m)		
			s.send(m)					
			while True:			
				seg = s.recv(1024)			
				if not seg:
					break
				else:
					data += seg.decode("utf-8")	
			cnt += 1
			s.close()
		except Exception as e: 
			print(e)
			print(cnt)
			print('msg: ' + str(m))
			err = {}
			err['error'] =  e
			err['msg'] = m
			report.append(err)
			s.close()			
			open_p = []
			pre_p = port
			time.sleep(5)
			for p in range(49153, 49157):
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				if s.connect_ex((host, p)) == 0:
					open_p.append(p)
			print(open_p)
			for p in open_p:
				if p != pre_p:
					port = p
					print('using port: ' + str(port))
					break
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

def mutate(msg):
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
				if i == cur:
					flow += p.encode() + chr(deli[i]).encode()
				else:
					flow += part[i] + chr(deli[i]).encode()
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
