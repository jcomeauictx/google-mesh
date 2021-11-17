#!/usr/bin/python3
'''
Decode Google Mesh diagnostic-report
'''
import sys, os, logging  # pylint: disable=multiple-imports
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
MARKERS = defaultdict(lambda: 'unimplemented', {
    b'\x0a': 'string',
    b'\x12': 'entry',
    b'\x1a': 'sysctl',
    b'\x22': 'unknown0',  # b'"'
    b'\x2a': 'unknown1',  # b'*'
})

def decode(data=None, filename=None, stack=None, dumpdir=None):
    '''
    Decode compressed document
    '''
    stack = stack if stack is not None else []
    begun = bool(dumpdir)
    if data is None and filename:
        with open(filename, 'rb') as infile:
            data = infile.read()
    offset = 0
    while offset < len(data):
        marker = data[offset:offset + 1]
        logging.debug('marker: %r (%s)', marker, MARKERS[marker])
        # pylint: disable=eval-used
        offset = eval(MARKERS[marker])(data, offset + 1, stack)
        logging.debug('stack: %s', stack)
        if not begun and filename and len(stack) == 1:
            dumpdir = os.path.join(
                'diagnostics',
                datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat(),
                stack.pop().rstrip()
            )
            os.makedirs(dumpdir, exist_ok=True)
            os.chdir(dumpdir)
            begun = True
        elif begun and MARKERS[marker] == 'entry':
            substack = []
            entrydata = stack.pop(-1)
            decode(entrydata, None, substack, dumpdir)
            if len(substack) >= 2:
                with open(os.path.join(dumpdir, substack.pop(0)),
                          'wb') as outfile:
                    outfile.write(substack.pop(0))
                logging.debug('remaining substack: %s', substack)
            else:
                raise ValueError(
                    'Decode of %r failed: %s' % (entrydata, substack))

def string(data, offset, stack):
    '''
    retrieve variable length string from data
    '''
    bytestring, offset = varbytes(data, offset)
    text = bytestring.decode()
    stack.append(text)
    return offset

def entry(data, offset, stack):
    '''
    retreive file name, data, and possibly other attributes

    a subentry is data only
    '''
    bytestring, offset = varbytes(data, offset)
    stack.append(bytestring)
    return offset

def sysctl(data, offset, stack):
    '''
    return supposed sysctl setting
    '''
    return string(data, offset, stack)

def unknown0(data, offset, stack):
    '''
    return unknown identifier
    '''
    return string(data, offset, stack)

def unknown1(data, offset, stack):
    '''
    return uknown data, possibly attached to unknown identifier preceding
    '''
    return entry(data, offset, stack)

def unimplemented(data, offset, stack):
    '''
    raise NotImplementedError
    '''
    raise NotImplementedError(
        'Unknown marker byte at offset 0x%x: %r' % (
            offset, data[offset:offset + 64]))

def varbytes(data, offset):
    '''
    Get variable length string and return new offset
    '''
    length, offset = varint(data, offset)
    return data[offset:offset + length], offset + length

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
    decode(None, sys.argv[1])
