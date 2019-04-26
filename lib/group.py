import lib.extract
import lib.exp
from collections import Counter
import math
import pdb
import json
import xmltodict

def divide(msgs, index, pre_key, entr):
	msg_cnt = len(msgs)
	groups = []
	key = []
	type_num = []
	#find the key index
	cur_index = index
	uni_msg = []
	for m in msgs:
		if m.req in [u.req for u in uni_msg]:
			continue
		else:
			uni_msg.append(m)
	if len(uni_msg) == 1:
		return [group(msgs[0].parts, msgs)]
	#check whether need to terminate
	while cur_index < len(msgs[0].all_seg):		
		cnt = Counter([m.all_seg[cur_index] for m in uni_msg])
		key_set = cnt.keys()
		cv = list(cnt.values())
		#if Counter(cv)[1] / len(uni_msg) < 0.5:
		if entropy([m.all_seg[cur_index] for m in uni_msg]) < entr:
			if msgs[0].all_seg[cur_index - 2] == b'Content-Length':	#for HTTP
				cur_index += 1
			elif set(key_set) == {b'0', b'1'}:	#boolean field
				cur_index += 1
			elif len(key_set) == 1:
				pre_key += [cur_index]
				cur_index +=1
			else:	
				break
		else:
			cur_index += 1
	if cur_index == len(msgs[0].all_seg):	#in the end of msg
		return [group(pre_key, msgs)]

	#if len(key_set) > 1:
	#	pdb.set_trace()
		
		
	for key in key_set:
		subset = [msg for msg in msgs if msg.all_seg[cur_index] == key]
		groups += divide(subset, cur_index + 1, pre_key + [cur_index], entr)
	
	return groups

def entropy(input_l):
	en = 0.0
	l = len(input_l)
	if l < 2:
		return 0
	input_set = set(list(input_l))
	for s in input_set:
		freq = input_l.count(s) / len(input_l)
		en += freq * math.log(freq, 2)
	en /= math.log(l, 2)
	return -en


def data_type(s):
	if s == '':
		return ''
	try:
		float(s)
		if s.find('.') == -1:
			return 'int'
		else:
			return 'float'
	except:
		return 'string'

def dict_cnt(data):
	cnt = 0
	for v in data.values():
		if isinstance(v, dict):
			cnt += dict_cnt(v)
		elif isinstance(v, list):
			cnt += len(v)
		else:
			cnt += 1
	return cnt

class group:
	def __init__(self, key_index, member):
		self.index = -1
		self.key_index = key_index
		self.member = [m.index for m in member]
		self.msgs = member
		self.keys = [None] * len(member[0].parts)
		self.fields = [None] * len(member[0].parts)
		self.deli_order = [d for d in member[0].deli_order]
		if len(set(m.req for m in member)) == 1:
			self.keys = member[0].parts
			return

		for i in range(len(member[0].parts)):
			if i in key_index:
				self.keys[i] = member[0].parts[i]
			else:	#s>i>f>''>none
				for f in [m.parts[i] for m in member]:
					if data_type(f) == 'string':
						self.fields[i] = 'string'
					elif data_type(f) == 'int' and self.fields[i] != 'string':
						self.fields[i] = 'int'
					elif data_type(f) == 'float' and self.fields[i] != 'string' and self.fields[i] != 'int':
						self.fields[i] = 'float'
					elif data_type(f) == '' and self.fields[i] == None:
						self.fields[i] = ''
		self.v_cnt = 0
		self.show_result()
	
	def __repr__(self):
		re = b'\nGroup: ' + str(self.index).encode() + b'\n' + b'member: ' + str(self.member).encode() + b'\n'
		#re += 'Keys: ' + str(self.keys) + '\nFields' + str(self.fields) + '\n'
		l = len(self.keys)
		deli = self.deli_order + [32]
		for i in range(l):
			if self.fields[i] == None:
				re += self.keys[i]
			else:
				#re += self.fields[i].encode()
				re += '____'.encode()
			re += chr(deli[i]).encode()
		return bytes.decode(re) + self.show_result()
		
	def show_result(self):
		data = {}
		req = self.msgs[0].req.decode()
		data = lib.exp.to_dict(req)
		if isinstance(data, dict):
			v_cnt = dict_cnt(data)
		else:
			v_cnt = 0
		self.v_cnt = v_cnt
		f_cnt = len([f for f in self.fields if f != None])
		#print('Total value: %d\t Identified: %d\n' % (v_cnt, f_cnt))
		return '\nTotal value: %d\t Identified: %d\n' % (v_cnt, f_cnt)
