import os
import sys
import hashlib

walk_dir = sys.argv[1]


def md5_for_file(path, block_size=2**20):
	f = open(path)
	md5 = hashlib.md5()
	
	while True:
		data = f.read(block_size)
		if not data:
			break
		md5.update(data)
		
	f.close()
	return md5.digest().encode("hex")

for root, subdirs, files in os.walk(walk_dir):
	for file in files:
		print file + " : ",
		print hashlib.md5(open(root +"\\"+ file, 'rb').read()).hexdigest()
#		print md5_for_file(root +"\\"+ file)

