#!/usr/bin/env python3
"""Build a US-only experimental synthetic-chip candidate. No device testing implied."""
import argparse
import json
import struct
import zipfile
from pathlib import Path
from patch_scanner_closed import (sha256, inspect_container, verify_image, digest,
                                 PROFILES, BEFORE, AFTER)

SOURCE = 'f78f7554db98e1b108bcbd28d1781389ae507bb7f1967ba08cee6792965948a4'
READ_ADDRESS = 0x48974
READ_OFFSET = READ_ADDRESS - 0xd000

# ARM state, little endian. Replace the hardware chip reader with an in-process
# 40-byte record. The original function receives a pointer to a 40-byte cache.
# This invokes stock dummy-cartridge recognition (fields 7/8/9 = 1/5/4),
# rather than changing the independent error aggregators or their return values.
WORDS = [
    0xe3a03000,       # mov r3, #0: index
    0xe3a0c000,       # mov ip, #0: zero
    0xe7c2c003,       # strb ip, [r2, r3]
    0xe2833001,       # add r3, r3, #1
    0xe3530028,       # cmp r3, #40
    0x3afffffb,       # blo clear loop
    0xe3a03001, 0xe5c23007,
    0xe3a03005, 0xe5c23008,
    0xe3a03004, 0xe5c23009,
    0xe3a03003, 0xe5c2300d, 0xe5c2300e,
    0xe3a0306e, 0xe5c23021,
    0xe3a00000,       # mov r0, #0: original success convention
    0xe12fff1e,       # bx lr
]
READER = struct.pack('<'+'I'*len(WORDS), *WORDS)


def build(source, output, report_path):
    if output.exists() or report_path.exists():
        raise ValueError('Refusing to overwrite existing outputs')
    if sha256(source.read_bytes()) != SOURCE:
        raise ValueError('Only the exact original US EFU is accepted')
    with zipfile.ZipFile(source) as z:
        if len(z.infolist()) != 1 or z.testzip() is not None:
            raise ValueError('Unexpected source ZIP')
        member=z.infolist()[0]
        rcx=z.read(member)
    start, meta, original, part2=inspect_container(rcx)
    profile=PROFILES[SOURCE]
    if sha256(original)!=profile['part1_sha256']:
        raise ValueError('Original IPL mismatch')
    changed=bytearray(original)
    edits=[]
    for off,after in [(o,AFTER) for o in profile['offsets']]+[(READ_OFFSET,READER)]:
        before=original[off:off+len(after)]
        if off in profile['offsets'] and before!=BEFORE:
            raise ValueError('Unexpected scanner instruction')
        changed[off:off+len(after)]=after
        edits.append(dict(ipl_offset=hex(off),runtime_address=hex(off+0xd000),
                          before=before.hex(),after=after.hex()))
    struct.pack_into('<H',changed,0x22,sum(changed[0x3000:])&0xffff)
    changed[0x40:0x54]=digest(changed)
    verify_image(changed)
    allowed={0x22,0x23}|set(range(0x40,0x54))
    for edit in edits:
        off=int(edit['ipl_offset'],16)
        allowed.update(range(off,off+len(bytes.fromhex(edit['after']))))
    differences=[i for i,(a,b) in enumerate(zip(original,changed)) if a!=b]
    assert len(changed)==len(original) and set(differences)<=allowed
    result=rcx[:start]+changed+part2
    newstart,newmeta,newpart1,newpart2=inspect_container(result)
    assert (newstart,newmeta,newpart2)==(start,meta,part2)
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        z.writestr(member,result,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(output) as z:
        assert z.testzip() is None and z.read(member.filename)==result
    report=dict(status='EXPERIMENTAL_CANDIDATE',variant='US',device_tested=False,
                source_efu_sha256=SOURCE,output_efu_sha256=sha256(output.read_bytes()),
                patched_part1_sha256=sha256(newpart1),instructions=edits,
                changed_byte_offsets=[hex(i) for i in differences],
                metadata_unchanged=True,part2_unchanged=True,
                purpose='Synthetic dummy-cartridge read records; stock recognition and stock full-level branch; scanner closed retained.',
                limitations='Boot, physical chip absence, printing, ink-level display and recovery have NOT been tested on a printer.')
    report_path.parent.mkdir(parents=True,exist_ok=True)
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--manifest',required=True,type=Path)
    a=p.parse_args()
    print(json.dumps(build(a.source,a.output,a.manifest),indent=2))
