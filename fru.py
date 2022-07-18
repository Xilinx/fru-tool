# -*- coding: utf-8 -*-
# fru.py - Generate a binary IPMI FRU data file.
# Copyright (c) 2017 Dell Technologies
# Copyright (c) 2018 Kurt McKee <contactme@kurtmckee.org>
#
# https://github.com/genotrance/fru-tool/
#
# Licensed under the terms of the MIT License:
# https://opensource.org/licenses/MIT

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import itertools
import os
import struct
import sys

try:
    import configparser
except ImportError:
    # noinspection PyPep8Naming
    import ConfigParser as configparser

try:
    # noinspection PyUnresolvedReferences,PyUnboundLocalVariable
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


__version__ = '3.0.0'

EXTRAS = [
    'extra1', 'extra2', 'extra3',
    'extra4', 'extra5', 'extra6',
    'extra7', 'extra8', 'extra9',
]


def read_config(path):
    parser = configparser.ConfigParser()
    parser.read(path)

    try:
        config = {
            section.decode('ascii'): {
                option.decode('ascii'): parser.get(section, option).strip('"')
                for option in parser.options(section)
            }
            for section in parser.sections()
        }
    except AttributeError:
        config = {
            section: {
                option: parser.get(section, option).strip('"')
                for option in parser.options(section)
            }
            for section in parser.sections()
        }

    integers = [
        ('common', 'size'),
        ('common', 'version'),
    ]

    hex_integers = [
        ('board', 'date'),
        ('board', 'language'),
        ('chassis', 'type'),
        ('product', 'language'),
    ]

    for section in ['internal', 'chassis', 'board', 'product', 'multirecord']:
        if config['common'].get(section, '0') != '1' and section in config:
            del(config[section])
        if section in config['common']:
            del(config['common'][section])

    for section, option in integers:
        if section in config and option in config[section]:  # pragma: nobranch
            config[section][option] = int(config[section][option])

    for section, option in hex_integers:
        if section in config and option in config[section]:
            config[section][option] = int(config[section][option], 16)

    # Normalize the internal info area data.
    if config.get('internal', {}).get('data'):
        config['internal']['data'] = config['internal']['data'].encode('utf8')
    elif config.get('internal', {}).get('file'):
        internal_file = os.path.join(
            os.path.dirname(path), config['internal']['file']
        )
        try:
            with open(internal_file, 'rb') as f:
                config['internal']['data'] = f.read()
        except FileNotFoundError:
            message = 'Internal info area file {} not found.'
            raise ValueError(message.format(internal_file))
    if 'file' in config.get('internal', {}):
        del(config['internal']['file'])
    if 'internal' in config and not config['internal'].get('data'):
        del(config['internal'])

    return config


def validate_checksum(blob, offset, length):
    """Validate a chassis, board, or product checksum.

    *blob* is the binary data blob, and *offset* is the integer offset that
    the chassis, board, or product info area starts at.

    :type blob: bytes
    :type offset: int
    :type length: int
    """

    checksum = ord(blob[offset + length - 1:offset + length])
    data_sum = sum(
        struct.unpack('%dB' % (length - 1), blob[offset:offset + length - 1])
    )
    if 0xff & (data_sum + checksum) != 0:
        raise ValueError('The data does not match its checksum.')


def extract_values(blob, offset, names):
    """Extract values that are delimited by type/length bytes.

    The values will be extracted into a dictionary. They'll be saved to keys
    in the same order that keys are provided in *names*. If there are more
    values than key names then additional keys will be generated with the
    names *extra1*, *extra2*, and so forth.

    :type blob: bytes
    :type offset: int
    :type names: list[union(str, unicode)]
    """

    data = {}

    extras = ('extra%d' % i for i in itertools.count(1))  # pragma: nobranch
    for name in itertools.chain(names, extras):  # pragma: nobranch
        type_length = ord(blob[offset:offset + 1])
        if type_length == 0xc1:
            return data
        length = type_length & 0x3f
        encoding = (ord(blob[offset:offset+1]) & 0xc0) >> 6
        #encoding 3 means ascii, encoding 0 means binary
        if encoding == 3:
            data[name] = blob[offset+1 :offset + length+1].decode('ascii').strip('\x00').strip()
        else:
            data[name] = blob[offset+1 :offset + length+1].hex().strip()

        offset += length + 1

def extract_freeform_values(blob, offset, lengths, names):
    data={}
    for name,length in  zip(names,lengths):
        if name != 'null':
            if (length & 0xc0) >> 6 == 3:
                length = length & 0x3f
                data[name] = blob[offset :offset + length].decode('ascii').strip('\x00').strip()
            else:
                data[name] = blob[offset :offset + length].hex().strip()
        offset += length
    return data

def load(path=None, blob=None):
    """Load binary FRU information from a file or binary data blob.

    If *path* is provided, it will be read into memory. If *blob* is provided
    it will be used as-is.

    :type path: union(str, unicode)
    :type blob: bytes
    """

    if not path and not blob:
        raise ValueError('You must specify *path* or *blob*.')
    if path and blob:
        raise ValueError('You must specify *path* or *blob*, but not both.')

    if path:
        with open(path, 'rb') as f:
            blob = f.read()

    validate_checksum(blob, 0, 8)

    version = ord(blob[0:1])
    internal_offset = ord(blob[1:2]) * 8
    chassis_offset = ord(blob[2:3]) * 8
    board_offset = ord(blob[3:4]) * 8
    product_offset = ord(blob[4:5]) * 8
    multirecord_offset = ord(blob[5:6]) * 8
    data = {'common': {'version': version, 'size': len(blob)}}

    if internal_offset:
        next_offset = chassis_offset or board_offset or product_offset
        internal_blob = blob[internal_offset + 1:next_offset or len(blob)]
        data['internal'] = {'data': internal_blob}

    if chassis_offset:
        length = ord(blob[chassis_offset + 1:chassis_offset + 2]) * 8
        validate_checksum(blob, chassis_offset, length)

        data['chassis'] = {
            'type': ord(blob[chassis_offset + 2:chassis_offset + 3]),
        }
        names = ['part', 'serial']
        data['chassis'].update(extract_values(blob, chassis_offset + 3, names))

    if board_offset:
        length = ord(blob[board_offset + 1:board_offset + 2]) * 8
        validate_checksum(blob, board_offset, length)

        data['board'] = {
            'language': ord(blob[board_offset + 2:board_offset + 3]),
            'date': sum([
                ord(blob[board_offset + 3:board_offset + 4]),
                ord(blob[board_offset + 4:board_offset + 5]) << 8,
                ord(blob[board_offset + 5:board_offset + 6]) << 16,
            ]),
        }
        names = ['manufacturer', 'product', 'serial', 'part', 'fileid', 'revision', 'pcieinfo', 'uuid']
        data['board'].update(extract_values(blob, board_offset + 6, names))
        #as per xilinx spec, pcieinfo is split up with four different fields with each being 2 bytes (vendor, device, subvendor, subdevice)
        #pcie info also expected to be displayed in hex
        if 'pcieinfo' in data['board']:
            temp  = data['board']['pcieinfo']
            data['board']['pcieinfo'] = { \
                'Vendor_ID':temp[0:4], \
                'Device_ID':temp[4:8], \
                'SubVendor_ID':temp[8:12], \
                'SubDevice_ID':temp[12:16] \
            }

    if multirecord_offset:
        if blob[multirecord_offset:multirecord_offset+1] == b'\x02':
            dcloadrecord_offset = 0x68
            names = ['output_number', 'nominal_voltage', 'min_V','max_V','ripple/noise_pk-pk_mV','min_mA','max_mA']
            lengths = [1,2,2,2,2,2,2]
            data['multirecord']={'DC_Load_Record': extract_freeform_values(blob, dcloadrecord_offset+5, lengths, names)}

            # Convert little endian hex data to decimal
            temp_val = data['multirecord']['DC_Load_Record']['output_number']
            data['multirecord']['DC_Load_Record']['output_number'] = int(temp_val, 16)
            temp_names = ['nominal_voltage', 'min_V','max_V']
            for name in temp_names:
                temp_val = [data['multirecord']['DC_Load_Record'][name][i:i+2] for i in range(0,4,2)]
                data['multirecord']['DC_Load_Record'][name] = int("".join(temp_val[::-1]), 16)/100
            temp_names = ['ripple/noise_pk-pk_mV','min_mA','max_mA']
            for name in temp_names:
                temp_val = [data['multirecord']['DC_Load_Record'][name][i:i+2] for i in range(0,4,2)]
                data['multirecord']['DC_Load_Record'][name] = int("".join(temp_val[::-1]), 16)

        if (path.split("/")[5].split("-")[1] == '0050'): #som is 0050

            SOM_macaddr_offset = 0x7A
            if blob[SOM_macaddr_offset:SOM_macaddr_offset+1] == b'\xd2':
                names=['Xilinx_IANA_ID','Version','MAC_ID_0']
                lengths=[3,1,6]
                data['multirecord'].update({'MAC_Addr':extract_freeform_values(blob, SOM_macaddr_offset+5, lengths, names)})

            #SOM_memconf_offset was 0x9B for legacy devices, Memory Config record will be skipped for these devices
            SOM_memconf_offset = 0x89
            if blob[SOM_memconf_offset:SOM_memconf_offset+1] == b'\xd3':
                names=['Xilinx_IANA_ID','null','Primary_boot_device','null','null','SOM_secondary_boot_device','null','null','SOM_PS_DDR_memory','null','null','SOM_PL_DDR_memory','null']
                #aligning with spec for board area where bits 7:6 define encoding, or-ing length with 0xc0 if ascii data
                lengths=[3,8,12|0xc0,1,8,12|0xc0,1,8,12|0xc0,1,8,12|0xc0,1]
                data['multirecord'].update({'SoM_Memory_Config':extract_freeform_values(blob, SOM_memconf_offset+5, lengths, names)})

        elif (path.split("/")[5].split("-")[1] == '0051'): #cc is 0051

            if (data['board']['product'].split("-")[1].lower() == "kv"):
                CC_macaddr_offset = 0x7A
                if blob[CC_macaddr_offset:CC_macaddr_offset+1] == b'\xd2':
                    names=['Xilinx_IANA_ID','Version','MAC_ID_0']
                    lengths=[3,1,6]
                    data['multirecord'].update({'MAC_Addr':extract_freeform_values(blob, CC_macaddr_offset+5, lengths, names)})

            elif (data['board']['product'].split("-")[1].lower() == "kr"):
                CC_macaddr_offset = 0x7A
                if blob[CC_macaddr_offset:CC_macaddr_offset+1] == b'\xd2':
                    names=['Xilinx_IANA_ID','Version','PS_MAC_ID_1','PL_MAC_ID_0','PL_MAC_ID_1']
                    lengths=[3,1,6,6,6]
                    data['multirecord'].update({'MAC_Addr':extract_freeform_values(blob, CC_macaddr_offset+5, lengths, names)})

                CC_ethercat_addr_offset = 0x95
                if blob[CC_ethercat_addr_offset:CC_ethercat_addr_offset+1] == b'\xd2':
                    names=['Xilinx_IANA_ID','Version','Xilinx_EtherCAT_ID']
                    lengths=[3,1,4]
                    data['multirecord'].update({'EtherCAT_Addr':extract_freeform_values(blob, CC_ethercat_addr_offset+5, lengths, names)})

    if product_offset:
        length = ord(blob[product_offset + 1:product_offset + 2]) * 8
        validate_checksum(blob, product_offset, length)

        data['product'] = {
            'language': ord(blob[product_offset + 2:product_offset + 3]),
        }
        names = [
            'manufacturer', 'product', 'part', 'version',
            'serial', 'asset', 'fileid',
        ]
        data['product'].update(extract_values(blob, product_offset + 3, names))

    return data


def dump(data):
    if 'common' not in data:
        raise ValueError('[common] section missing in config')

    if 'version' not in data['common']:
        raise ValueError('"version" missing in [common]')

    if 'size' not in data['common']:
        raise ValueError('"size" missing in [common]')

    internal_offset = 0
    chassis_offset = 0
    board_offset = 0
    product_offset = 0
    multirecord_offset = 0

    internal = bytes()
    chassis = bytes()
    board = bytes()
    product = bytes()

    if data.get('internal', {}).get('data'):
        internal = make_internal(data)
    if 'chassis' in data:
        chassis = make_chassis(data)
    if 'board' in data:
        board = make_board(data)
    if 'product' in data:
        product = make_product(data)

    pos = 1
    if len(internal):
        internal_offset = pos
        pos += len(internal) // 8
    if len(chassis):
        chassis_offset = pos
        pos += len(chassis) // 8
    if len(board):
        board_offset = pos
        pos += len(board) // 8
    if len(product):
        product_offset = pos

    # Header
    out = struct.pack(
        'BBBBBBB',
        data['common'].get('version', 1),
        internal_offset,
        chassis_offset,
        board_offset,
        product_offset,
        multirecord_offset,
        0x00
    )

    # Checksum
    out += struct.pack('B', (0 - sum(bytearray(out))) & 0xff)

    blob = out + internal + chassis + board + product
    difference = data['common']['size'] - len(blob)
    pad = struct.pack('B' * difference, *[0] * difference)

    if len(blob + pad) > data['common']['size']:
        raise ValueError('Too much content, does not fit')

    return blob + pad


def make_internal(data):
    return struct.pack(
        'B%ds' % len(data['internal']['data']),
        data['common'].get('version', 1),
        data['internal']['data'],
    )


def make_chassis(config):
    out = bytes()

    # Type
    out += struct.pack('B', config['chassis'].get('type', 0))

    # Strings
    fields = ['part', 'serial']

    # Handle extras, if any.
    max_extra = max([
        int(key[5:])
        for key in config['chassis']
        if key.startswith('extra')
    ] or [0])
    if max_extra:
        fields.extend(['extra{}'.format(i) for i in range(1, max_extra + 1)])

    for k in fields:
        if config['chassis'].get(k):
            value = config['chassis'][k].encode('ascii')
            out += struct.pack('B%ds' % len(value), len(value) | 0xC0, value)
        else:
            out += struct.pack('B', 0)

    # No more fields
    out += struct.pack('B', 0xC1)

    # Padding
    while len(out) % 8 != 5:
        out += struct.pack('B', 0)

    # Header version and length in bytes
    out = struct.pack(
        'BB',
        config['common'].get('version', 1),
        (len(out) + 3) // 8,
    ) + out

    # Checksum
    out += struct.pack('B', (0 - sum(bytearray(out))) & 0xff)

    return out


def make_board(config):
    out = bytes()

    # Language
    out += struct.pack('B', config['board'].get('language', 0))

    # Date
    date = config['board'].get('date', 0)
    out += struct.pack(
        'BBB',
        (date & 0xFF),
        (date & 0xFF00) >> 8,
        (date & 0xFF0000) >> 16,
    )

    # String values
    fields = ['manufacturer', 'product', 'serial', 'part', 'fileid']

    # Handle extras, if any.
    max_extra = max([
        int(key[5:])
        for key in config['board']
        if key.startswith('extra')
    ] or [0])
    if max_extra:
        fields.extend(['extra{}'.format(i) for i in range(1, max_extra + 1)])

    for key in fields:
        if config['board'].get(key):
            value = config['board'][key].encode('ascii')
            out += struct.pack('B%ds' % len(value), len(value) | 0xC0, value)
        else:
            out += struct.pack('B', 0)

    # No more fields
    out += struct.pack('B', 0xC1)

    # Padding
    while len(out) % 8 != 5:
        out += struct.pack('B', 0)

    # Header version and length in bytes
    out = struct.pack(
        'BB',
        config['common'].get('version', 1),
        (len(out)+3) // 8,
    ) + out

    # Checksum
    out += struct.pack('B', (0 - sum(bytearray(out))) & 0xff)

    return out


def make_product(config):
    out = bytes()

    # Language
    out += struct.pack('B', config['product'].get('language', 0))

    # Strings
    fields = [
        'manufacturer', 'product', 'part', 'version', 'serial', 'asset',
        'fileid',
    ]

    # Handle extras, if any.
    max_extra = max([
        int(key[5:])
        for key in config['product']
        if key.startswith('extra')
    ] or [0])
    if max_extra:
        fields.extend(['extra{}'.format(i) for i in range(1, max_extra + 1)])

    for key in fields:
        if config['product'].get(key):
            value = config['product'][key].encode('ascii')
            out += struct.pack('B%ds' % len(value), len(value) | 0xC0, value)
        else:
            out += struct.pack('B', 0)

    # No more fields
    out += struct.pack('B', 0xC1)

    # Padding
    while len(out) % 8 != 5:
        out += struct.pack('B', 0)

    # Header version and length in bytes
    out = struct.pack(
        'BB',
        config['common'].get('version', 1),
        (len(out) + 3) // 8,
    ) + out

    # Checksum
    out += struct.pack('B', (0 - sum(bytearray(out))) & 0xff)

    return out


def run(ini_file, bin_file):  # pragma: nocover
    try:
        configuration = read_config(ini_file)
        blob = dump(configuration)
    except ValueError as error:
        print(error.message)
    else:
        with open(bin_file, 'wb') as f:
            f.write(blob)


if __name__ == '__main__':  # pragma: nocover
    if len(sys.argv) < 3:
        print('fru.py input.ini output.bin [--force] [--cmd]')
        sys.exit()

    if not os.path.exists(sys.argv[1]):
        print('Missing INI file %s' % sys.argv[1])
        sys.exit()

    if os.path.exists(sys.argv[2]) and '--force' not in sys.argv:
        print('BIN file %s exists' % sys.argv[2])
        sys.exit()

    run(sys.argv[1], sys.argv[2])
