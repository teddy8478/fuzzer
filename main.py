from lib import extract, group
import re

msgs = extract.read_pcap('log/ftp')
group.div_format(msgs)
