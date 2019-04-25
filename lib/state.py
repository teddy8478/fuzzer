import pdb
import re
from collections import Counter

def rm_cyc(msgs):
	ret = []
	trace = []
	for i in range(msgs[-1].file + 1):
		trace.append([m.group.index for m in msgs if m.file == i])
	reduced = []
	for t in trace:
		s = str(t)[1:-1].replace(',', '')	
		regex = re.compile(r' (.+)( \1)+ ')
		while True:
			match = regex.search(s)
			if not hasattr(match, 'group'):
				final = s.split(' ')
				reduced.append(list(map(int,final)))
				break
			s = s.replace(match.group(0), ' ' + match.group(1) + ' ')		
				
	tr_msg = []
	for i in range(msgs[-1].file + 1):
		tr_msg.append([m for m in msgs if m.file == i])
	for i in range(len(reduced)):
		ret.append([])
		for j in range(len(tr_msg[i])):
			if len(reduced[i]) == 0:
				break
			if tr_msg[i][j].group.index == reduced[i][0]:
				ret[-1].append(tr_msg[i][j])
				reduced[i].pop(0)
		#print([m.group.index for m in ret[-1]])
	return ret
		

def construct(traces):	#construct FSM tree
	root = state(0, None)
	final = state(1, None)
	#build the tree
	#print(traces)
	sid = 2
	state_list = [root, final]
	leaf = []
	end = set()
	tr = 0
	for trace in traces:
		trace = [m.group.index for m in trace]
		cur = root
		for i in range(len(trace)-1):
			if trace[i] in cur.trans.keys():
				cur = cur.trans[trace[i]]
			else:
				new = state(sid, cur)
				sid += 1
				cur.add_child(trace[i], new)
				cur = new
				state_list.append(new)
			cur.trace.append(tr)
		tr += 1
		leaf.append(cur)
		end.add(cur.index)
		cur.prefix.append(tr)	
		cur.leaf = True
		cur.add_child(trace[-1], final)
	
	#find the equivalent state
	while(True):		
		for i in range(len(leaf)):
			for j in range(i+1, len(leaf)):
				if same_state(leaf[i], leaf[j]):
					leaf[i].equal.append(leaf[j].index)
					leaf[j].equal.append(leaf[i].index)
		for i in range(len(leaf)):
			leaf[i].parent.postfix.add(leaf[i].index)
			leaf[i].parent.postfix = leaf[i].parent.postfix | leaf[i].postfix
			leaf[i] = leaf[i].parent
		if root in leaf:
			break
		leaf = list(set(leaf))
	equal_list = []
	for s in [set(s.equal) for s in state_list if len(s.equal) > 1]:
		if s not in equal_list:
			equal_list.append(s)
	print(equal_list)

	#merge equivalent state
	lv = 0
	while True:
		lv += 1
		cur_lv = [s.index for s in state_list if s.lv == lv]
		if len(cur_lv) == 0 or len(equal_list) == 0:
			break
		for c in cur_lv:
			merge = [Set for Set in equal_list if c in Set]
			if len(merge) == 0:
				continue
			merge = list(merge[0])
			for m in merge[1:]:
				parent_act = state_list[m].parent.trans
				pre_act = [act for act, child in parent_act.items() if child.index == m][0]
				state_list[m].parent.trans[pre_act] = state_list[merge[0]]
				#remove the subtree
				state_list[m].leaf = True
				end.add(m)
				for i in range(len(equal_list)):
					equal_list[i] -= state_list[m].postfix
					equal_list[i] -= {m}
				end.add(state_list[m].parent.index)
				state_list[m].parent.trans[pre_act] = state_list[1]
				end -= state_list[m].postfix
				end -= {m}
				#pdb.set_trace()
			equal_list = [s for s in equal_list if len(s) > 1]
	#print(end)
	return root, end, state_list
		
def same_state(s1, s2):
	if s1.trans.keys() != s2.trans.keys():
		return False
	for act in s1.trans.keys():
		if s2.trans[act].index not in s1.trans[act].equal and s1.trans[act].index not in s2.trans[act].equal:
			return False
	return True
	
class state:
	def __init__(self, index, parent):
		self.index = index
		self.parent = parent
		self.trans = {}
		self.equal = [index]
		self.prefix = []
		self.postfix = set()
		self.trace = []
		self.leaf = False
		self.remain = []
		if index == 0:
			self.lv = 0
		elif index == 1:
			self.lv = None
		else:
			self.lv = parent.lv + 1
	
	def __repr__(self):
		if self.index == 0:
			re = 'root'
		elif self.index == 1:
			re = 'final'
		else:
			re = 'State ' + str(self.index)
			re += '\nparent: ' + str(self.parent.index)
			re += '\nchild: ' + str({k: v.index for k, v in self.trans.items() }) + '\n'

		return re

	def add_child(self, act, s):
		self.trans[act] = s
		self.remain.append(act)
