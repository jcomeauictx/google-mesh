#!/usr/bin/python3
'''
Decode Google Mesh diagnostic-report
'''
import sys, logging  # pylint: disable=multiple-imports

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
MARKER = b'\x12'  # ^R marks entries

def decode(filename):
    '''
    Decode compressed document
    '''
    with open(filename, 'rb') as infile:
        data = infile.read()
    offset = data.index(MARKER)
    print(data[:offset].decode())
    while offset < len(data):
        chunklength, offset = varint(data, offset + 1)
        if data[offset + chunklength] != MARKER:
            raise ValueError(
                'Marker not found at 0x%x: %s' % (
                    offset + chunklength,
                    data[offset + chunklength:offset + chunklength + 64]
                )
            )

def varint(data, offset):
    '''
    Decode variable integer and return new offset
    '''
    value = 0
    while True:
        byte = data[offset]
        logging.debug('varint: byte=0x%x', byte)
        value = (value << 7) + (byte & 0x7f)
        offset += 1
        if byte & 0x80 == 0:
            break
    logging.debug('value: 0x%x', value)
    return value, offset

if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.argv.append('diagnostic-report')
    decode(sys.argv[1])
