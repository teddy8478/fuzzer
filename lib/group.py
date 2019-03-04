import lib.extract
from collections import Counter
import pdb

def divide(msgs, index, pre_key):
	msg_cnt = len(msgs)
	groups = []
	key = []
	type_num = []
	#find the key index
	for i in range(index, len(msgs[0].parts)):
		type_num.append(len(Counter([m.parts[i] for m in msgs])))
		if {m.parts[i] for m in msgs} == {''}:
			type_num[-1] = 10000
	cur_index = index + type_num.index(min(type_num))

	#check whether need to terminate
	uni_msg = []
	for m in msgs:
		if m.req in [u.req for u in uni_msg] and len(pre_key) > 0:
			continue
		else:
			uni_msg.append(m)
	cnt = Counter([m.parts[cur_index] for m in uni_msg])
	key_set = cnt.keys()
	cv = list(cnt.values())
	if Counter(cv)[1] / len(uni_msg) > 0.5 or index + 1  == len(msgs[0].parts):
		return [group(pre_key, msgs)]

	for key in key_set:
		subset = [msg for msg in msgs if msg.parts[cur_index] == key]
		groups += divide(subset, cur_index + 1, pre_key + [cur_index])
	
	return groups

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
						
	
	def __repr__(self):
		re = ''
		re += 'Keys: ' + str(self.keys) + '\nFields' + str(self.fields) + '\n'
		return re
		

