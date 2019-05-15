from lib import group
import pdb
import math

def find_rule(traces, g_num):
	#rule[i][j] = (a, b) means index a in group i req equals index b in group j resp
	print('Finding rule...')
	rules = [[None] * g_num for _ in range(g_num)]  
	for tr in traces:
		pre_msg = [None] * g_num
		for msg in tr:
			g = msg.group.index
			for m in range(g_num):
				if pre_msg[m] == None:
					rules[g][m] = set()
					continue
				if m == msg.group.index or rules[g][m] == set():	
					continue
				if rules[g][m] == None:	#first time
					rules[g][m] = compare_field(msg, pre_msg[m])
				else:
					rules[g][m] = rules[g][m] & compare_field(msg, pre_msg[m])
			pre_msg[g] = msg
	ret = [[] for i in range(g_num)]
	cnt = 0
	for i in range(g_num):
		for j in range(len(rules[i])):
			if rules[i][j] == None:
				continue
			if len(rules[i][j]) > 0:
				for s in rules[i][j]:
					if s[0] not in {r[0] for r in ret[i]}:	#one field one rule
						ret[i].append((s[0], j, s[1]))
						cnt += 1
	return ret, cnt
							
def compare_field(m1, m2):
	ret = set()
	for i in range(len(m1.parts)):
		if group.entropy(m1.parts[i]) <= 0.6 or m1.group.fields[i] == None or (m1.parts[i] in m1.group.resp_keys):
			continue
		for j in range(len(m2.resp_parts)):
			if m1.group.fields[i] == None:
				continue
			if m1.parts[i] == m2.resp_parts[j]:
				#pdb.set_trace()
				#print('%s %d %d'%(m1.parts[i], m1.group.index, m2.group.index))
				ret.add((i, j))
	return ret

def entropy_str(input_l):
	en = 0.0
	l = len(input_l)
	if l < 2:
		return 0
	input_set = set(list(input_l))
	for s in input_set:
		freq = input_l.count(s) / len(input_l)
		en += freq * math.log(freq, 2)
	return -en


