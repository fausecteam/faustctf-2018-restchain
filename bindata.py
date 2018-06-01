#!/usr/bin/env python3

import sys

print('package main')
print()
print('var bindata = map[string][]byte{')
for line in sys.stdin:
	dest, fname = line.strip().split(None, 1)
	# print('//', repr(dest), repr(fname), file=sys.stderr)
	with open(fname, 'rb') as f:
		print('\t', '"', dest, '": []byte("', sep='', end='')
		print(''.join('\\x{:02x}'.format(c) for c in f.read()), end='')
		print('"),')
		pass
print('}')
