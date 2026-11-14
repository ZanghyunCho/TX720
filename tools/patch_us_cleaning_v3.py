#!/usr/bin/env python3
"""US v3 candidate: retain v2; remove only the normal cleaning dummy early return.

Uses native-decoder-derived literal blocks. Native output verification is a
separate tool. Does not communicate with or test a printer.
"""
import argparse
import json
import struct
import zipfile
from pathlib import Path
from patch_scanner_closed import sha256, inspect_container, digest, verify_image

PLAN_PATH=Path(__file__).with_name('us-cleaning-crom-plan.json')


def repack(part2,plan):
    if sha256(part2)!=plan['original_part2_sha256']:
        raise ValueError('Unexpected v2 second IPL')
    start=plan['stream_file_offset'];length=plan['original_stream_length']
    if part2[start-4:start]!=b'CROM':raise ValueError('CROM magic mismatch')
    stream=part2[start:start+length];chunks=[];cursor=0
    for edit in plan['blocks']:
        lo=edit['stream_start'];hi=edit['stream_end']
        if not cursor<=lo<hi<=length:raise ValueError('Invalid block boundaries')
        if sha256(stream[lo:hi])!=edit['original_compressed_sha256']:
            raise ValueError('Compressed block does not match original')
        literal=bytes.fromhex(edit['replacement_hex'])
        if literal[:1]!=b'\x20' or struct.unpack_from('<H',literal,1)[0]!=len(literal)-3:
            raise ValueError('Invalid literal-block plan')
        chunks.extend([stream[cursor:lo],literal]);cursor=hi
    chunks.append(stream[cursor:]);newstream=b''.join(chunks)
    growth=len(newstream)-length
    if growth<0 or part2[start+length:start+length+growth]!=b'\xff'*growth:
        raise ValueError('Repacked stream does not fit existing erased padding')
    changed=bytearray(part2);changed[start:start+len(newstream)]=newstream
    struct.pack_into('<H',changed,0x22,sum(changed[0x3000:])&0xffff)
    changed[0x40:0x54]=digest(changed);verify_image(changed)
    allowed={0x22,0x23}|set(range(0x40,0x54))|set(range(start,start+len(newstream)))
    assert len(changed)==len(part2)
    assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(part2,changed)))
    return bytes(changed),growth


def build(source,output,manifest):
    if output.exists() or manifest.exists():raise ValueError('Refusing to overwrite outputs')
    plan=json.loads(PLAN_PATH.read_text())
    source_hash=sha256(source.read_bytes())
    if source_hash!=plan['source_v2_sha256']:raise ValueError('Only exact published US v2 is accepted')
    with zipfile.ZipFile(source) as z:
        if len(z.infolist())!=1 or z.testzip() is not None:raise ValueError('Bad input ZIP')
        info=z.infolist()[0];rcx=z.read(info)
    start,meta,part1,part2=inspect_container(rcx)
    newpart2,growth=repack(part2,plan)
    result=rcx[:start]+part1+newpart2
    newstart,newmeta,newpart1,checked=inspect_container(result)
    assert (newstart,newmeta,newpart1,checked)==(start,meta,part1,newpart2)
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        z.writestr(info,result,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(output) as z:assert z.testzip() is None and z.read(info.filename)==result
    report=dict(revision=3,status='EXPERIMENTAL_CANDIDATE',variant='US',
                source_v2_sha256=source_hash,output_efu_sha256=sha256(output.read_bytes()),
                part1_sha256=sha256(part1),modified_part2_sha256=sha256(newpart2),
                part1_unchanged_from_v2=True,metadata_unchanged=True,
                compressed_stream_growth=growth,compressed_blocks_replaced=len(plan['blocks']),
                decoded_change={'address':plan['decoded_instruction_address'],
                                'before':plan['before'],'after':plan['after'],
                                'meaning':'Replace normal-cleaning caller dummy check with mov r0,#0; retain global dummy recognition elsewhere.'},
                device_tested=False,physical_cleaning_verified=False,
                note='Native decoder output and dispatch comparison must be verified separately; no device access.')
    manifest.parent.mkdir(parents=True,exist_ok=True);manifest.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--manifest',type=Path,required=True);a=p.parse_args()
    print(json.dumps(build(a.source,a.output,a.manifest),indent=2))
