import pdb
import json
import xmltodict
from urllib import parse
import sys

def result(msgs, groups):
	dict_l = parse_dict(msgs)
	g_cnt = len(dict_l)
	ident = [0] * g_cnt
	for g in groups:
		g_dict = to_dict(str(g).replace('____', '0'))
		if not isinstance(g_dict, dict):
			continue
		for i in range(g_cnt):
			if dict_sim(g_dict, dict_l[i]) == 1:
				ident[i] = 1
				break
	ident_cnt = ident.count(1)
	if g_cnt == 0:
		cov =0
	else:
		cov = ident_cnt / g_cnt
	#pdb.set_trace()
	print('Real group: %d\tIdentified: %d\tCoverage: %f' % (g_cnt, ident_cnt, cov))


def dict_keys(d):
	key = []
	#pdb.set_trace()
	for k in d.keys():
		key += [k]
		if isinstance(d[k], dict):
			key += dict_keys(d[k])
	return key

def dict_sim(d1, d2):
	diff = len(set(dict_keys(d1)) - set(dict_keys(d2)))
	#if diff == 0:
	#	pdb.set_trace()
	return 1 - diff / len(d1)

def to_dict(s):
	ret = s
	data = {}
	try:
		js = ret[ret.find('{'): ret.rfind('}') + 1]
		data = json.loads(js)
		return data
	except:
		pass

	try:
		#pdb.set_trace()
		xml = ret[ret.find('<'): ret.rfind('>') + 1]
		data = xmltodict.parse(xml)
		return data
	except:
		pass
	'''
	if sys.argv[1] == 'router':
		pdb.set_trace()
		line = s.split('\r\n')

		return parse.parse_qs(s)
	'''
	return ''

def parse_dict(msgs):	#return a list of dict parsed from json or xml
	ret = []
	
	for m in msgs:
		data = to_dict(m.req.decode())
		exist = 0
		if not isinstance(data, dict):
			continue
		for r in ret:
			if dict_sim(r, data) == 1:
				#pdb.set_trace()
				exist = 1
				break
		if not exist:
			ret.append(data)

	return ret
