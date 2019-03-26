#!/usr/bin/env python3
from lib import extract, group, fuzz, state
import re
import time

import pdb

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
#print(group_list)
#print(msgs[-1].parts)

#for g in group_list:
#fuzz.tcp_fuzz(fuzz.mutate(g.msgs[0]))

trace = []
for i in range(msgs[-1].file + 1):
	trace.append([m.group.index for m in msgs if m.file == i])
trace = state.rm_cyc(trace)
pdb.set_trace()
tree_root, end, s_list = state.construct(trace)
#fuzz.start(tree_root, end, s_list, msgs)


