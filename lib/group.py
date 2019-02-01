def div_format(msgs):
	form = {}
	for msg in msgs:
		parts = re.split(' |:|/|&|=|\r|\n|,', msg['req'])
		order = msg
		for part in parts:
			order.replace(part, '')
		if form[order]:
			form[order].append(msg)
		else:
			form[order] = [msg]

class group:
	def __init(self, msg, keys):
		parts = re.split(' |:|/|&|=|\r|\n|,', msg['req'])
		self.len = len(parts)
		for key in keys:
			self.(key, parts[key])
		
