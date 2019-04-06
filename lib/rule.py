def find_rule(msgs):
	trace = []
	for i in range(msgs[-1].file + 1):
		trace.append([m for m in msgs if m.file == i])
	

class rule:
	def __init__(self, src_g, src_pos, dist_g, dist_pos):
		self.src_g = src_g
		self.src_pos = src_pos
		self.dist_g = dist_g
		self.dist_pos = dist_pos
