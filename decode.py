#!/usr/bin/python3
'''
Decode Google Mesh diagnostic-report
'''
import sys, logging  # pylint: disable=multiple-imports

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
MARKER = b'\x12'  # ^R marks entries
MARKERS = {
    b'\x0a': 'filename',
    MARKER: 'entry',
    b'\x1a': 'sysctl',
    b'"': 'unknown0',  # b'\x22'
    b'*': 'unknown1',  # b'\x2a'
}

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
        if data[offset + chunklength:offset + chunklength + 1] not in MARKERS:
            raise ValueError(
                'Marker not found at 0x%x: %s' % (
                    offset + chunklength,
                    data[offset + chunklength:offset + chunklength + 64]
                )
            )
        end_chunk = offset + chunklength
        if data[offset:offset + 1] != b'\x0a':
            raise ValueError(
                'Filename not found at 0x%x: %s' % (
                    offset,
                    data[offset:offset + 64]
                )
            )
        offset += 1
        namelength, offset = varint(data, offset)
        filename = data[offset:offset + namelength].decode()
        logging.debug('processing file: %s', filename)
        offset += namelength
        if data[offset:offset + 1] != MARKER:
            raise ValueError(
                'Marker not found at 0x%x: %s' % (
                    offset + chunklength,
                    data[offset + chunklength:offset + chunklength + 64]
                )
            )
        chunklength, offset = varint(data, offset + 1)
        if offset + chunklength < end_chunk:
            offset += chunklength  # skip file data
            if data[offset:offset + 1] == b'\x1a':
                logging.debug('found sysctl alias to previous data')
                chunklength, offset = varint(data, offset + 1)
                logging.debug('sysctl: %s',
                              data[offset:offset + chunklength].decode())
            else:
                raise ValueError(
                    'Unrecognized marker %r' % data[offset:offset + 1])
        if offset + chunklength != end_chunk:
            raise ValueError(
                'Discrepancy in end_chunk: 0x%x != 0x%x' % (
                    offset + chunklength,
                    end_chunk
                )
            )
        offset = end_chunk

def varint(data, offset):
    '''
    Decode variable integer and return new offset
    '''
    value = 0
    partial = []
    while True:
        byte = data[offset]
        partial.append(byte & 0x7f)
        logging.debug('varint: byte=0x%x, partial=%s', byte, partial)
        offset += 1
        if byte & 0x80 == 0:
            break
    while partial:
        byte = partial.pop(-1)
        value = (value << 7) + byte
    logging.debug('varint: value=0x%x', value)
    return value, offset

if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.argv.append('diagnostic-report')
    decode(sys.argv[1])
