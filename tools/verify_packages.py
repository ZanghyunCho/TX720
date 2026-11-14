#!/usr/bin/env python3
"""Verify both committed experimental EFUs offline; does not access a printer."""
import hashlib
import json
from pathlib import Path
import zipfile

from patch_scanner_closed import AFTER, PROFILES, inspect_container
from patch_us_chipless_candidate import (READ_OFFSET, READER, STATUS_API,
    FILTER_ADDRESS, STATUS_FILTER, LEVEL_GETTER, FULL_LEVEL, arm_branch)
import struct


def main():
    root = Path(__file__).resolve().parents[1]
    for variant in ['jp', 'us']:
        report = json.loads((root/'reports'/f'{variant}-patch.json').read_text())
        profile = PROFILES[report['source_efu_sha256']]
        filename = f'FWC365TL_{variant.upper()}_scanner_closed_EXPERIMENTAL.efu'
        file = root/'firmware'/filename
        if hashlib.sha256(file.read_bytes()).hexdigest() != report['patched_efu_sha256']:
            raise ValueError(f'{filename}: package SHA-256 mismatch')
        with zipfile.ZipFile(file) as archive:
            if len(archive.infolist()) != 1 or archive.testzip() is not None:
                raise ValueError(f'{filename}: archive validation failed')
            rcx = archive.read(archive.namelist()[0])
        _, metadata, first, _ = inspect_container(rcx)
        if hashlib.sha256(first).hexdigest() != report['patched_part1_sha256']:
            raise ValueError(f'{filename}: first IPL SHA-256 mismatch')
        for offset in profile['offsets']:
            if first[offset:offset+4] != AFTER:
                raise ValueError(f'{filename}: patched instruction mismatch')
        if f'3="{profile["version"]}"' not in metadata or f'12="{profile["target"]}"' not in metadata:
            raise ValueError(f'{filename}: target/version mismatch')
        validation = json.loads((root/'reports'/f'{variant}-arm-validation.json').read_text())
        if validation['status'] != 'passed' or validation['variant'] != variant.upper():
            raise ValueError(f'{filename}: missing ARM execution results')
        print(f'{filename}: SHA-256, ZIP CRC, both IPL checksums/SHA-1, patch and metadata OK')
    filename='FWC365TL_US_chipless_candidate_v1_EXPERIMENTAL.efu'
    file=root/'firmware'/filename
    report=json.loads((root/'reports/us-chipless-candidate-v1-patch.json').read_text())
    validation=json.loads((root/'reports/us-chipless-candidate-v1-validation.json').read_text())
    package_hash=hashlib.sha256(file.read_bytes()).hexdigest()
    if package_hash!=report['output_efu_sha256'] or package_hash!=validation['package_sha256']:
        raise ValueError('US chipless candidate package/report hash mismatch')
    with zipfile.ZipFile(file) as z:
        if len(z.infolist())!=1 or z.testzip() is not None:raise ValueError('Bad candidate ZIP')
        _,metadata,first,second=inspect_container(z.read(z.namelist()[0]))
    if hashlib.sha256(first).hexdigest()!=report['patched_part1_sha256']:
        raise ValueError('Candidate IPL hash mismatch')
    if first[READ_OFFSET:READ_OFFSET+len(READER)]!=READER:
        raise ValueError('Candidate reader mismatch')
    for off in PROFILES[report['source_efu_sha256']]['offsets']:
        if first[off:off+4]!=AFTER:raise ValueError('Candidate scanner patch missing')
    with zipfile.ZipFile(root/'firmware/FWC365TL_US_scanner_closed_EXPERIMENTAL.efu') as z:
        _,oldmeta,oldfirst,oldsecond=inspect_container(z.read(z.namelist()[0]))
    allowed={0x22,0x23}|set(range(0x40,0x54))|set(range(READ_OFFSET,READ_OFFSET+len(READER)))
    differences={i for i,(a,b) in enumerate(zip(first,oldfirst)) if a!=b}
    if metadata!=oldmeta or second!=oldsecond or len(first)!=len(oldfirst) or not differences<=allowed:
        raise ValueError('Candidate modified unexpected bytes')
    if validation['status']!='passed' or validation['synthetic_reader_cases']!=3072 or validation['stock_acceptance_cases']!=1536 or validation['stock_packet_mode_cases']!=256:
        raise ValueError('Missing candidate native validation')
    print(f'{filename}: package integrity, exact edits, stock-function execution report OK; device UNTESTED')
    baseline=first
    filename='FWC365TL_US_chipless_candidate_v2_EXPERIMENTAL.efu'
    file=root/'firmware'/filename
    report=json.loads((root/'reports/us-chipless-candidate-v2-patch.json').read_text())
    validation=json.loads((root/'reports/us-chipless-candidate-v2-validation.json').read_text())
    reader=json.loads((root/'reports/us-chipless-candidate-v2-reader-validation.json').read_text())
    package_hash=hashlib.sha256(file.read_bytes()).hexdigest()
    if any(package_hash!=r[k] for r,k in [(report,'output_efu_sha256'),(validation,'package_sha256'),(reader,'package_sha256')]):
        raise ValueError('US v2 package/report hash mismatch')
    with zipfile.ZipFile(file) as z:
        if len(z.infolist())!=1 or z.testzip() is not None:raise ValueError('Bad v2 ZIP')
        _,newmeta,newfirst,newsecond=inspect_container(z.read(z.namelist()[0]))
    allowed={0x22,0x23}|set(range(0x40,0x54))
    for address,code in [(FILTER_ADDRESS,STATUS_FILTER),(STATUS_API,struct.pack('<I',arm_branch(STATUS_API,FILTER_ADDRESS))),
                         (LEVEL_GETTER,FULL_LEVEL)]:
        off=address-0xd000
        allowed.update(range(off,off+len(code)))
        if newfirst[off:off+len(code)]!=code:raise ValueError('v2 code mismatch')
    differences={i for i,(a,b) in enumerate(zip(newfirst,baseline)) if a!=b}
    if newmeta!=metadata or newsecond!=second or len(newfirst)!=len(baseline) or not differences<=allowed:
        raise ValueError('v2 modified unexpected bytes')
    if hashlib.sha256(newfirst).hexdigest()!=report['patched_part1_sha256']:
        raise ValueError('v2 IPL hash mismatch')
    if validation['status']!='passed' or validation['normalized_api_cases']!=4096 or validation['gui_level_getter_cases']!=1536 or len(validation['native_error_decision_cases'])!=30 or reader['status']!='passed':
        raise ValueError('Missing v2 native validation')
    print(f'{filename}: integrity, exact edits, status API and native error comparisons OK; device UNTESTED')


if __name__ == '__main__':
    main()
