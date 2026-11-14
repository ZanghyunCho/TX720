#!/usr/bin/env python3
"""Experimental US v4: preserve v3 and suppress only the CR delay query.

No printer communication. This removes one motor thermal-protection delay;
software verification does not establish safe motor temperature.
"""
import argparse
import json
import zipfile
from pathlib import Path
from patch_scanner_closed import inspect_container, sha256
from patch_us_cleaning_v3 import repack

PLAN_PATH=Path(__file__).with_name('us-cr-wait-crom-plan.json')

def build(source,output,manifest):
    if output.exists() or manifest.exists():
        raise ValueError('Refusing to overwrite outputs')
    plan=json.loads(PLAN_PATH.read_text())
    if sha256(source.read_bytes())!=plan['source_v3_sha256']:
        raise ValueError('Only the exact published US v3 is accepted')
    with zipfile.ZipFile(source) as z:
        if len(z.infolist())!=1 or z.testzip() is not None:
            raise ValueError('Invalid source container')
        info=z.infolist()[0];rcx=z.read(info)
    start,meta,p1,p2=inspect_container(rcx)
    changed,growth=repack(p2,plan)
    result=rcx[:start]+p1+changed
    assert inspect_container(result)==(start,meta,p1,changed)
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        z.writestr(info,result,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(output) as z:
        assert z.testzip() is None and z.read(info.filename)==result
    report=dict(revision=4,status='EXPERIMENTAL_CR_WAIT_BYPASS',variant='US',
        source_v3_sha256=sha256(source.read_bytes()),output_efu_sha256=sha256(output.read_bytes()),
        first_ipl_unchanged_from_v3=True,metadata_unchanged=True,
        modified_part2_sha256=sha256(changed),compressed_stream_growth=growth,
        decoded_change=dict(address=plan['decoded_instruction_address'],
            before=plan['before'],after=plan['after'],
            meaning='Xtensa CR delay query: movi.n a2,0; ret.n. PF delay query remains original.'),
        existing_v3_patches_retained=True,device_tested=False,
        physical_speed_improvement_verified=False,thermal_safety_verified=False,
        warning='Bypasses one CR motor heat-protection delay. Overheating and motor/driver damage are possible. No motor-temperature measurement or hardware validation was performed.')
    manifest.parent.mkdir(parents=True,exist_ok=True)
    manifest.write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--manifest',type=Path,required=True);a=p.parse_args()
    print(json.dumps(build(a.source,a.output,a.manifest),indent=2))
