#!/usr/bin/env python3
from lib import extract, group, fuzz, state
import re
import time
import pdb
'''
data = ['GET iot/device?id=1&type=2',
		'GET iot/device?id=20&type=1',
		'GET iot/temprature?num=3&s=aaa',
		'GET iot/temprature?num=5&s=bbb',
		'DELETE device?id=9\r\n']
msgs=[]
i = 0
for d in data:
	msgs.append(extract.msg(i, d, '', 0))
	i += 1
'''
msgs = extract.read_pyshark('log/plug')
#msgs = extract.read_pcap_test('../pulsar/example.pcap')
group_list = []

tStart = time.time()
for order in set(m.deli_order for m in msgs):	#divide by order of delimiter and pass to divide
	l = [m for m in msgs if m.deli_order == order]
	group_list += group.divide(l, 0, [])
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
print(fuzz.mutate(msgs[3]))
#for m in msgs:
#fuzz.tcp_fuzz([m for m in msgs if m.file == 0])

trace = []
for i in range(msgs[-1].file + 1):
	trace.append([m.group.index for m in msgs if m.file == i])
tree_root, end, s_list = state.construct(trace)
#fuzz.start(tree_root, end, s_list, msgs)


