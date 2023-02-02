#!/usr/bin/env python

from __future__ import print_function
import sys
import re


def add_definition(k, v):
    print('#define {} ({})'.format(k, v))


def hex_normalize(h):
    d = int(h, 0)
    return hex(d)


def main():
    ptn = sys.argv[1]

    with open(ptn, 'r') as f:
        line = f.readline()

        m = re.search(r'flash\s*=\s*(\d+)([KMG])', line)
        size = int(m.group(1))
        unit = m.group(2)
        if unit == 'M':
            size = size << 20
        else:
            raise RuntimeError('Unsupported unit {}'.format(unit))
        add_definition('NM_FLASH_SIZE', hex(size))

        m = re.search(r'total\s*=\s*(\d+)', line)
        ptn_num = int(m.group(1))

        dual = False
        for i in range(ptn_num):
            line = f.readline()
            m = re.match(r'\d+=\s*(.+)', line)
            line = m.group(1)
            info = re.split(r'\s*,\s*', line)
            if info[0].startswith('partition-table'):
                m = re.match(r'partition-table@(\d+)', info[0])
                if m is None:
                    add_definition('NM_PTN_TABLE_BASE', info[1])
                    add_definition('NM_PTN_TABLE_SIZE', info[2])
                else:
                    idx = int(m.group(1))
                    add_definition('NM_PTN_TABLE_BASE_{}'.format(idx), info[1])
                    add_definition('NM_PTN_TABLE_SIZE_{}'.format(idx), info[2])
                    dual = True
        if dual:
            add_definition('NM_DUAL_IMAGE', '1')

if __name__ == '__main__':
    sys.exit(main())
