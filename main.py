#!/usr/bin/env python3
from lib import extract, group, fuzz, state, rule, exp
import re
import time
import sys
import pdb

ip = '192.168.200.5'
port = 49153
conn = (ip, port)
msgs = extract.read_pyshark('log/' + sys.argv[1])
#msgs = extract.read_pcap_test('../pulsar/example.pcap')
tStart = time.time()
entr = 0.05
pre_cnt = -1
pre_list = []
while entr <= 1:
	cur_list = []
	req_deli = set(m.deli_order for m in msgs)
	print('clustering...')
	for order in req_deli:	#divide by order of delimiter and pass 
		l = [m for m in msgs if m.deli_order == order]
		resp_order = set(n.resp_deli for n in l)
		for resp_o in resp_order:
			resp_l = [m for m in l if m.resp_deli == resp_o] 
			cur_list += group.divide(resp_l, 0, [], entr)
	cur_list.sort(key = lambda g: g.member[0])
	#pdb.set_trace()
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
	entr += 0.05
group_list = pre_list	

group_list.sort(key = lambda g: g.member[0])
tEnd = time.time()
print("clustering time: %f sec" % (tEnd - tStart))
for i in range(len(group_list)):
	group_list[i].index = i
	for m in group_list[i].member:
		msgs[m].group = group_list[i]
group_order = [m.group.index for m in msgs]

trace = []
#pdb.set_trace()
trace = state.rm_cyc(msgs)
for tr in trace:
	print([m.group.index for m in tr])
rules, rule_num = rule.find_rule(trace, len(cur_list))
exp.result(msgs, group_list)
print(group_list)
print(rules)
#pdb.set_trace()
tree_root, end, s_list = state.construct(trace)
print('start fuzzing...')
#fuzz.tplink_fuzz(fuzz.mutate(group_list[4].msgs[0], dict()), conn)
fuzz.start(tree_root, end, s_list, trace, conn, rules)





