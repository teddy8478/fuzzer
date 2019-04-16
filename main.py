#!/usr/bin/env python3
from lib import extract, group, fuzz, state, rule
import re
import time

import pdb

ip = '192.168.200.5'
port = 49153
conn = (ip, port)
msgs = extract.read_pyshark('log/tplink')
#msgs = extract.read_pcap_test('../pulsar/example.pcap')
pdb.set_trace()
tStart = time.time()
entr = 1.5
pre_cnt = 0
pre_list = []
while entr <= 3:
	cur_list = []
	for order in set(m.deli_order for m in msgs):	#divide by order of delimiter and pass 
		l = [m for m in msgs if m.deli_order == order]
		cur_list += group.divide(l, 0, [], entr)
	cur_list.sort(key = lambda g: g.member[0])	
	for i in range(len(cur_list)):
		cur_list[i].index = i
		for m in cur_list[i].member:
			msgs[m].group = cur_list[i]

	trace = []
	trace = state.rm_cyc(msgs)

	rules, rule_num = rule.find_rule(trace, len(cur_list))
	print('%f %d' % (entr, rule_num))
	if rule_num < pre_cnt:
		break
	elif rule_num > pre_cnt:
		pre_list = cur_list
		pre_cnt = rule_num
	entr += 0.25

group_list = pre_list	
#pdb.set_trace()

group_list.sort(key = lambda g: g.member[0])
tEnd = time.time()
print("clustering time: %f sec" % (tEnd - tStart))
for i in range(len(group_list)):
	group_list[i].index = i
	for m in group_list[i].member:
		msgs[m].group = group_list[i]
group_order = [m.group.index for m in msgs]
print(group_list)
pdb.set_trace()
trace = []
trace = state.rm_cyc(msgs)
for tr in trace:
	print([m.group.index for m in tr])
rules, rule_num = rule.find_rule(trace, len(cur_list))
print(rules)
pdb.set_trace()
tree_root, end, s_list = state.construct(trace)
print('start fuzzing...')
fuzz.start(tree_root, end, s_list, trace, conn)


