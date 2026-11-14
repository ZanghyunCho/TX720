#!/usr/bin/env python3
"""Native CROM decoding + old/new normal-cleaning dispatch comparison. No device."""
import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path
from patch_scanner_closed import inspect_container,sha256
from patch_us_cleaning_v3 import PLAN_PATH


def validate(root,package,output):
    sys.path.insert(0,str(root/'python-libs'))
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,
        UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)
    plan=json.loads(PLAN_PATH.read_text())
    with zipfile.ZipFile(package) as z:
        assert z.testzip() is None
        _,_,p1,p2=inspect_container(z.read(z.namelist()[0]))
    def machine():
        u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0,0x2000000);u.mem_map(0x40000000,0x4000000)
        u.mem_write(0x10000,p1[0x3000:]);u.mem_write(0x1000000,p2[0x3000:]);return u
    u=machine();decoded={};records=[];stop=0x1fff000
    def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
    def segment(uc,a,n,x):
        sp=uc.reg_read(UC_ARM_REG_SP);dst=word(sp+8);size=word(sp+4)
        assert (dst,size) in [(0x41a0d000,2436364),(0x40000000,767300),(0x43e51000,2972)]
        data=bytes(uc.mem_read(dst,size));decoded[dst]=data
        records.append(dict(destination=hex(dst),length=size,sha256=sha256(data),cursor=word(0x400d5920)))
    u.hook_add(UC_HOOK_CODE,segment,begin=0x1c8ce0,end=0x1c8ce0)
    u.reg_write(UC_ARM_REG_R0,0x695fe0);u.reg_write(UC_ARM_REG_R1,0x101343c)
    u.reg_write(UC_ARM_REG_SP,0x43fff000);u.reg_write(UC_ARM_REG_LR,stop)
    u.emu_start(0x1c8c40,stop,count=300000000)
    assert u.reg_read(UC_ARM_REG_PC)==stop and u.reg_read(UC_ARM_REG_R0)==1
    originals={base:(root/'us/crom-extracted'/f'{base:08x}.bin').read_bytes() for base in decoded}
    assert len(decoded)==3
    expected=bytearray(originals[0x41a0d000]);off=int(plan['decoded_instruction_address'],16)-0x41a0d000
    assert sha256(expected)==plan['decoded_original_sha256']
    assert expected[off:off+4]==bytes.fromhex(plan['before'])
    expected[off:off+4]=bytes.fromhex(plan['after'])
    assert decoded[0x41a0d000]==bytes(expected)
    assert sha256(decoded[0x41a0d000])==plan['decoded_modified_sha256']
    for base in [0x40000000,0x43e51000]:assert decoded[base]==originals[base]
    differences=[hex(0x41a0d000+i) for i,(a,b) in enumerate(zip(originals[0x41a0d000],decoded[0x41a0d000])) if a!=b]
    assert differences==[hex(int(plan['decoded_instruction_address'],16)+i) for i in range(4)]
    print('Native decoder: all three segments returned; exactly four intended code bytes differ.',flush=True)
    regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    results=[]
    for version,segments in [('v2',originals),('v3',decoded)]:
        m=machine()
        for base,data in segments.items():m.mem_write(base,data)
        events=[];configuration={'mode':1,'result':0,'ready':0}
        def ret(value=0):
            m.reg_write(UC_ARM_REG_R0,value);m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        def mode(uc,a,n,x):events.append(['mode-selector']);ret(configuration['mode'])
        def dispatch(uc,a,n,x):events.append(['hardware-dispatch',uc.reg_read(UC_ARM_REG_R0)]);ret(configuration['result'])
        def cleanup(uc,a,n,x):events.append(['cleanup']);ret()
        def ready(uc,a,n,x):ret(configuration['ready'])
        def idle(uc,a,n,x):ret(0)
        def acknowledge(uc,a,n,x):events.append(['reply',uc.reg_read(UC_ARM_REG_R1)]);ret()
        mocks={0x41a456b8:mode,0x41a434a0:dispatch,0x41a49cc4:cleanup,
               0x41a4cb64:ready,0x41a4b8cc:idle,0x41a46dd4:acknowledge}
        for a,f in mocks.items():m.hook_add(UC_HOOK_CODE,f,begin=a,end=a)
        def call(a,*args):
            for reg,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2],args):m.reg_write(reg,v)
            for i,reg in enumerate(regs):m.reg_write(reg,0xabc000+i)
            m.reg_write(UC_ARM_REG_SP,0x43fff000);m.reg_write(UC_ARM_REG_LR,stop)
            m.emu_start(a,stop,count=100000)
            assert m.reg_read(UC_ARM_REG_PC)==stop
            assert m.reg_read(UC_ARM_REG_SP)==0x43fff000
            assert [m.reg_read(r) for r in regs]==[0xabc000+i for i in range(8)]
            return m.reg_read(UC_ARM_REG_R0)
        for port,base in [(1,0x40136c70),(3,0x40136cc0),(2,0x40136c98),(5,0x40136d10),(4,0x40136ce8),(7,0x40136d60)]:
            assert call(0x48974,port,0xe0,base)==0
        assert call(0x41a35e4c)==1
        for selected in [1,2,3]:
            for result in [0,1,0x55]:
                configuration.update(mode=selected,result=result,ready=0)
                events.clear();answer=call(0x41a45738)
                wanted=[] if version=='v2' else [['mode-selector'],['hardware-dispatch',selected]]+([['cleanup']] if result else [])
                assert events==wanted,(version,events,wanted)
                assert answer==(0 if version=='v2' else result)
                results.append(dict(version=version,entry='normal-cleaning',mode=selected,dispatch_result=result,returned=answer,events=list(events)))
                # Original command-9 handler also exercises completion replies.
                m.mem_write(0x400c947e,b'\0');m.mem_write(0x43ffd000,b'\0'*32)
                events.clear();call(0x41a4866c,0x43ffd000)
                reply=0 if version=='v2' else int(result!=0)
                assert events==wanted+[['reply',reply]],(version,events)
                results.append(dict(version=version,entry='command-9-handler',mode=selected,dispatch_result=result,events=list(events)))
        # Existing early guards still prevent dispatch; no unconditional motion.
        configuration.update(mode=1,result=0,ready=0)
        m.mem_write(0x400c947e,b'\x10');events.clear();call(0x41a4866c,0x43ffd000)
        assert events==[['reply',0]]
        m.mem_write(0x400c947e,b'\0');configuration['ready']=1
        events.clear();call(0x41a4866c,0x43ffd000);assert events==[['reply',1]]
        assert call(0x41a35e4c)==1  # Global dummy recognition is retained.
    report=dict(status='passed',revision=3,package_sha256=sha256(package.read_bytes()),
                native_decoder_segments=records,decoded_changed_addresses=differences,
                other_decoded_segments_unchanged=True,global_dummy_recognition_retained=True,
                cleaning_comparisons=results,existing_early_guards_preserved=True,
                abi_preserved=True,device_tested=False,physical_cleaning_verified=False,
                scope='Native CROM decoder without mocks. Cleaning routine and command-9 handler execute native code; mode selector, hardware dispatcher, cleanup and ready/idle/reply boundaries are mocked. No physical motor/pump emulation.')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(results)} native cleaning/command comparisons; global dummy recognition and existing early guards retained.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--analysis-root',type=Path,required=True)
    p.add_argument('package',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    validate(a.analysis_root,a.package,a.output)
