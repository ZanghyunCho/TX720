#!/usr/bin/env python3
"""Reproduce the scanner-unit-closed experimental patches from exact original EFUs.

Uses only Python's standard library. Does not communicate with a printer.
The accepted hashes identify the two supplied originals, not all TX720 firmware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile


PROFILES = {
    '4bdcd6236ff9984422acbeb34367c54f3907b6efc9f6593683c38348ac042d62': {
        'variant': 'JP', 'version': '22.22.AJ06I7.FY10', 'target': 'AJ*FY10',
        'offsets': [0xdd824, 0xdd840],
        'part1_sha256': '5989e32cea8ca1102f93b29794bc9850ef48b2d2b19cf175ad965af22aa78447',
    },
    'f78f7554db98e1b108bcbd28d1781389ae507bb7f1967ba08cee6792965948a4': {
        'variant': 'US', 'version': '21.21.AW03G6.FY10', 'target': 'AW*FY10',
        'offsets': [0x11be2c, 0x11be48],
        'part1_sha256': '6fa67ff99fba51882772fa15164800129c70f9fa2518e3a869e1f367b45f81d4',
    },
}
BEFORE = bytes.fromhex('a00fa0e1')  # ARM lsr r0, r0, #31
AFTER = bytes.fromhex('0000a0e3')   # ARM mov r0, #0 (without changing flags)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(image):
    body_length = struct.unpack_from('<I', image, 0x2c)[0]
    if body_length + 0x3000 != len(image):
        raise ValueError('Unexpected IPL payload length')
    h = hashlib.sha1(image[0x3000:])
    h.update(hashlib.sha1(image[:14]).digest())
    return h.digest()


def verify_image(image):
    if image[:10] != b'EPSON IPL6' or struct.unpack_from('<H', image, 14)[0] != 0x30:
        raise ValueError('Unsupported IPL header')
    if struct.unpack_from('<I', image, 0x1c)[0] != 0x2000:
        raise ValueError('Unexpected updater-helper length')
    for field, body in [(0x12, image[0x1000:0x3000]), (0x22, image[0x3000:])]:
        if struct.unpack_from('<H', image, field)[0] != sum(body) & 0xffff:
            raise ValueError(f'IPL byte-sum mismatch at {field:#x}')
    if image[0x40:0x54] != digest(image):
        raise ValueError('IPL SHA-1 mismatch')


def inspect_container(rcx):
    start = rcx.index(b'\x0c') + 1
    metadata = rcx[:start].decode('ascii')
    lengths = [int(x) for x in re.findall(r'\[Z_\d+\].*?^5="(\d+)"', metadata, re.M | re.S)]
    if len(lengths) != 2 or start + sum(lengths) != len(rcx):
        raise ValueError('Unexpected RCX segmentation')
    a = rcx[start:start+lengths[0]]
    b = rcx[start+lengths[0]:]
    verify_image(a)
    verify_image(b)
    return start, metadata, a, b


def patch(source, output, manifest=None):
    source_hash = sha256(source.read_bytes())
    if source_hash not in PROFILES:
        raise ValueError('Unknown source EFU hash: refusing to guess offsets')
    profile = PROFILES[source_hash]
    if source.resolve() == output.resolve() or output.exists():
        raise ValueError('Output must be a new file, distinct from the source')
    if manifest is not None and (manifest.exists() or manifest.resolve() in {source.resolve(), output.resolve()}):
        raise ValueError('Manifest must be a new, distinct file')
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) != 1 or archive.testzip() is not None:
            raise ValueError('Invalid source archive')
        member = members[0]
        rcx = archive.read(member)
    start, metadata, original, part2 = inspect_container(rcx)
    if sha256(original) != profile['part1_sha256']:
        raise ValueError('Unexpected first IPL image')
    if f'3="{profile["version"]}"' not in metadata or f'12="{profile["target"]}"' not in metadata:
        raise ValueError('Unexpected target/version metadata')
    changed = bytearray(original)
    edits = []
    for offset in profile['offsets']:
        if changed[offset:offset+4] != BEFORE:
            raise ValueError(f'Unexpected instruction at {offset:#x}')
        changed[offset:offset+4] = AFTER
        edits.append({'ipl_file_offset':hex(offset), 'runtime_address':hex(offset+0xd000),
                      'before':BEFORE.hex(), 'after':AFTER.hex()})
    old_sum = struct.unpack_from('<H', original, 0x22)[0]
    new_sum = sum(changed[0x3000:]) & 0xffff
    struct.pack_into('<H', changed, 0x22, new_sum)
    changed[0x40:0x54] = digest(changed)
    verify_image(changed)
    allowed = {0x22,0x23} | set(range(0x40,0x54)) | {o+i for o in profile['offsets'] for i in range(4)}
    differences = [i for i,(a,b) in enumerate(zip(original, changed)) if a != b]
    if len(changed) != len(original) or not set(differences) <= allowed:
        raise ValueError('Unexpected modifications')
    modified_rcx = rcx[:start] + changed + part2
    # Round-trip validation of metadata, BOTH image integrity records, and image boundaries.
    new_start, new_metadata, new_part1, new_part2 = inspect_container(modified_rcx)
    if new_start != start or new_metadata != metadata or new_part2 != part2:
        raise ValueError('Metadata/second image changed')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(member, modified_rcx, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or archive.read(member.filename) != modified_rcx:
            raise ValueError('Output ZIP CRC/content mismatch')
    report = {
        'variant':profile['variant'], 'version':profile['version'], 'target':profile['target'],
        'source_efu_sha256':source_hash, 'patched_efu_sha256':sha256(output.read_bytes()),
        'original_part1_sha256':sha256(original), 'patched_part1_sha256':sha256(new_part1),
        'instructions':edits, 'changed_byte_offsets':[hex(x) for x in differences],
        'old_byte_sum':hex(old_sum), 'new_byte_sum':hex(new_sum),
        'old_sha1_field':original[64:84].hex(), 'new_sha1_field':changed[64:84].hex(),
        'integrity_checks':'ZIP CRC, helper byte-sum, payload byte-sum, salted SHA-1 passed',
        'part2_unchanged':True, 'metadata_unchanged':True, 'language_resources_unchanged':True,
        'device_tested':False,
    }
    if manifest is not None:
        manifest.parent.mkdir(parents=True, exist_ok=True)
        with manifest.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(patch(args.source, args.output, args.manifest), indent=2))
    except (ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Error: {error}\n')
