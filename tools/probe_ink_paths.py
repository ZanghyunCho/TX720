#!/usr/bin/env python3
"""Probe the original ink-status code; does NOT patch firmware or access a device.

Requires Unicorn 2.1.4 and original extracted IPL/CROM files produced during
analysis. Property access in the service predicate is stubbed explicitly below.
The error aggregator itself executes native firmware code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

PROFILES = {
    'jp': dict(aggregate=0x41acd1b0, state=0x40158474, converter=0x41acc138,
               percentage_getter=0x16030c, percentage_cache=0x400d5aeb,
               csic_predicate=0x41b18984, property_get=0x41bd4bf8,
               packet_parser=0x41acf0b8),
    'us': dict(aggregate=0x41ac0afc, state=0x4017ad54, converter=0x41abfa84,
               percentage_getter=0x1fd8a8, percentage_cache=0x400d5dbf,
               csic_predicate=0x1815e0, property_get=0x65a78,
               packet_parser=0x41ac2a04),
}

ORIGINAL_IPL_SHA256 = {
    'jp': '5989e32cea8ca1102f93b29794bc9850ef48b2d2b19cf175ad965af22aa78447',
    'us': '6fa67ff99fba51882772fa15164800129c70f9fa2518e3a869e1f367b45f81d4',
}


def run(analysis, variant, output):
    sys.path.insert(0, str(analysis/'python-libs'))
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)
    p=PROFILES[variant]
    work=analysis if variant=='jp' else analysis/'us'
    ipl=(work/'part1.ipl').read_bytes()
    digest=hashlib.sha256(ipl).hexdigest()
    if digest!=ORIGINAL_IPL_SHA256[variant]:
        raise ValueError(f'{variant}: original IPL SHA-256 mismatch')
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0,0x2000000)
    u.mem_map(0x40000000,0x4000000)
    u.mem_write(0x10000,ipl[0x3000:])
    input_hashes={'part1.ipl':digest}
    for base in [0x41a0d000,0x40000000,0x43e51000]:
        data=(work/'crom-extracted'/f'{base:08x}.bin').read_bytes()
        input_hashes[f'crom-extracted/{base:08x}.bin']=hashlib.sha256(data).hexdigest()
        u.mem_write(base,data)
    events=[]
    stop=0x1fff000
    state=p['state']

    def event_sink(u,address,size,user):
        # The aggregator stores a BYTE in its stack slot before loading r2.
        # Its downstream event receiver consumes that low byte; upper bits are not a bool.
        events.append([u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1),u.reg_read(UC_ARM_REG_R2)&0xff])
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))

    def property_get(u,address,size,user):
        key=u.reg_read(UC_ARM_REG_R0)
        count=u.reg_read(UC_ARM_REG_R2)
        if key!=0x42a or count!=6:
            raise AssertionError(f'Unexpected stub request {key:#x}/{count}')
        # Explicit service-layer stub: expose the ORIGINAL chip-state bytes.
        u.mem_write(u.reg_read(UC_ARM_REG_R1),bytes(u.mem_read(state+0x28,6)))
        u.reg_write(UC_ARM_REG_R0,6)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))

    u.hook_add(UC_HOOK_CODE,event_sink,begin=p['aggregate']+0x90,end=p['aggregate']+0x90)
    u.hook_add(UC_HOOK_CODE,property_get,begin=p['property_get'],end=p['property_get'])

    def call(address,r0=0,r1=0):
        u.reg_write(UC_ARM_REG_R0,r0)
        u.reg_write(UC_ARM_REG_R1,r1)
        u.reg_write(UC_ARM_REG_SP,0x43fff000)
        u.reg_write(UC_ARM_REG_LR,stop)
        u.emu_start(address,stop,count=10000)
        if u.reg_read(UC_ARM_REG_PC)!=stop or u.reg_read(UC_ARM_REG_SP)!=0x43fff000:
            raise AssertionError('Function did not return with its original stack')
        return u.reg_read(UC_ARM_REG_R0)

    results=[]
    cases=[('normal',None,0,None)]
    cases += [(f'chip-state-{code}-slot-{slot}',slot,code,None) for code in [2,3,4,5] for slot in range(6)]
    cases += [(f'end-status-0x85-slot-{slot}',None,0,slot) for slot in range(6)]
    for name,slot,code,end_slot in cases:
        u.mem_write(state+0x28,b'\0'*6)
        u.mem_write(state+0x40,b'\x83'*6)
        # Force reported remaining percentages ONLY, without changing chip/empty state.
        u.mem_write(p['percentage_cache'],b'\x64'*6)
        if slot is not None:u.mem_write(state+0x28+slot,bytes([code]))
        if end_slot is not None:u.mem_write(state+0x40+end_slot,b'\x85')
        percents=[call(p['percentage_getter'],i) for i in range(6)]
        if percents!=[100]*6:raise AssertionError('Native percentage getters did not return 100')
        events.clear()
        call(p['aggregate'])
        expected=0 if name=='normal' else 1
        if events!=[[0x88,0,expected]]:raise AssertionError(f'{name}: unexpected native events {events}')
        service_ok=call(p['csic_predicate'])
        if (slot is not None and code==4 and service_ok!=0) or (name=='normal' and service_ok!=1):
            raise AssertionError('CSIC predicate observation mismatch')
        results.append(dict(case=name,reported_percentages=percents,
                            native_error_event=events[-1],csic_service_predicate=service_ok))

    conversions=[]
    mapping={0:(0,1),1:(1,0),2:(2,3),3:(3,4),4:(4,2),5:(5,5)}
    for slot in range(6):
        for code in range(256):
            u.mem_write(state+0x28+slot,bytes([code]))
            u.mem_write(0x43ffe000,b'\xaa')
            value=call(p['converter'],slot,0x43ffe000)
            aux=u.mem_read(0x43ffe000,1)[0]
            if (value,aux)!=mapping.get(code,(4,2)):
                raise AssertionError('Native chip-state conversion mismatch')
        conversions.append(dict(slot=slot,input_codes_checked=256))
    report=dict(variant=variant.upper(),status='passed',firmware_modified=False,
                input_sha256=input_hashes,
                profiles={k:hex(v) for k,v in p.items()},
                cases=results,conversion_checks=conversions,
                counterexamples=30,
                finding='All-six 100% reported levels do not clear independent chip-state or 0x85 end-status errors.',
                scope='Original ARM functions with simulated RAM; property service and final event sink stubbed; no chip bus or printing emulation.')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(f'{variant.upper()}: {len(cases)} native aggregate cases and 1536 conversion cases passed; 30 counterexamples to percentage-only chipless.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis-root',required=True,type=Path)
    parser.add_argument('--output-dir',required=True,type=Path)
    a=parser.parse_args()
    for variant in ['jp','us']:run(a.analysis_root,variant,a.output_dir/f'{variant}-ink-path-probes.json')
