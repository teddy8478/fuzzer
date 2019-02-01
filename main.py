from lib import extract
import re

msgs = extract.read_pcap('log/ftp')

for msg in msgs:
	print(msg)
