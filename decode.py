#!/usr/bin/python3
'''
Decode Google Mesh diagnostic-report
'''
import sys
MARKER = b'\x12'  # ^R marks entries
def decode(filename):
    '''
    Decode compressed document
    '''
    with open(filename, 'rb') as infile:
        data = infile.read()
    offset = data.index(MARKER)
    print(data[:offset].decode())
if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.argv.append('diagnostic-report')
    decode(sys.argv[1])
