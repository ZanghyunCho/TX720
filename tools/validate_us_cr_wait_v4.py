#!/usr/bin/env python3
"""Verify US v4 with the original ARM CROM decoder; no device access.

Xtensa query execution is verified separately by CrWaitValidate.java.
"""
import argparse,json,struct,sys,zipfile
from pathlib import Path
from patch_scanner_closed import inspect_container,sha256
from patch_us_cr_wait_v4 import PLAN_PATH

def package(path):
    with zipfile.ZipFile(path) as z:
        assert len(z.infolist())==1 and z.testzip() is None
        return inspect_container(z.read(z.namelist()[0]))

def validate(root,source,candidate,output):
    sys.path.insert(0,str(root/'python-libs'))
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
    plan=json.loads(PLAN_PATH.read_text())
    assert sha256(source.read_bytes())==plan['source_v3_sha256']
    start,meta,p1,p2=package(candidate)
    oldstart,oldmeta,oldp1,oldp2=package(source)
    assert (start,meta,p1)==(oldstart,oldmeta,oldp1)
    assert sha256(oldp2)==plan['original_part2_sha256']
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0,0x2000000);u.mem_map(0x40000000,0x4000000)
    u.mem_write(0x10000,p1[0x3000:]);u.mem_write(0x1000000,p2[0x3000:])
    decoded={};records=[]
    def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
    def segment(uc,a,n,x):
        sp=uc.reg_read(UC_ARM_REG_SP);dst=word(sp+8);size=word(sp+4)
        assert (dst,size) in [(0x41a0d000,2436364),(0x40000000,767300),(0x43e51000,2972)]
        data=bytes(uc.mem_read(dst,size));decoded[dst]=data
        records.append(dict(destination=hex(dst),length=size,sha256=sha256(data),cursor=word(0x400d5920)))
    u.hook_add(UC_HOOK_CODE,segment,begin=0x1c8ce0,end=0x1c8ce0)
    u.reg_write(UC_ARM_REG_R0,0x695fe0);u.reg_write(UC_ARM_REG_R1,0x101343c)
    u.reg_write(UC_ARM_REG_SP,0x43fff000);u.reg_write(UC_ARM_REG_LR,0x1fff000)
    u.emu_start(0x1c8c40,0x1fff000,count=300000000)
    assert u.reg_read(UC_ARM_REG_PC)==0x1fff000 and u.reg_read(UC_ARM_REG_R0)==1
    assert len(decoded)==3
    originals={base:(root/'us/crom-extracted'/f'{base:08x}.bin').read_bytes() for base in decoded}
    code=bytearray(originals[0x41a0d000]);offset=0x41a4573c-0x41a0d000
    assert code[offset:offset+4]==bytes.fromhex('c2c1ffeb')
    code[offset:offset+4]=bytes.fromhex('0000a0e3')
    assert decoded[0x41a0d000]==bytes(code)  # v3 panel-cleaning correction retained
    xtensa=bytearray(originals[0x40000000]);offset=0xaaa78
    assert sha256(xtensa)==plan['decoded_original_sha256']
    assert xtensa[offset:offset+4]==bytes.fromhex(plan['before'])
    xtensa[offset:offset+4]=bytes.fromhex(plan['after'])
    if decoded[0x40000000]!=bytes(xtensa):
        mismatches=[(hex(0x40000000+i),a,b) for i,(a,b) in enumerate(zip(xtensa,decoded[0x40000000])) if a!=b]
        print('Unexpected decoded differences:',len(mismatches),mismatches[:24],flush=True)
        (root/'us/v4-debug-40000000.bin').write_bytes(decoded[0x40000000])
        raise AssertionError('Decoded Xtensa image differs from planned patch')
    assert sha256(xtensa)==plan['decoded_modified_sha256']
    assert decoded[0x43e51000]==originals[0x43e51000]
    differences=[hex(0x40000000+i) for i,(a,b) in enumerate(zip(originals[0x40000000],xtensa)) if a!=b]
    assert differences==[hex(0x400aaa78+i) for i in range(4)]
    report=dict(status='passed',revision=4,package_sha256=sha256(candidate.read_bytes()),
        native_decoder_segments=records,decoded_changes_relative_to_v3=differences,
        first_ipl_and_metadata_equal_to_v3=True,v3_panel_cleaning_correction_preserved=True,
        other_decoded_segments_equal_to_v3=True,pf_query_and_coefficients_unchanged=True,
        device_tested=False,thermal_safety_verified=False,
        scope='Original ARM CROM decoder executes without mocks. All decoded bytes match US v3 except four bytes at the Xtensa CR delay query. This verifies container/decoder integrity, not physical cooling or motor temperature.')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analysis-root',type=Path,required=True)
    p.add_argument('source_v3',type=Path);p.add_argument('candidate',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    validate(a.analysis_root,a.source_v3,a.candidate,a.output)
