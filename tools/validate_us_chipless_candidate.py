#!/usr/bin/env python3
"""Execute candidate ARM reader + stock dummy recognition, isolated from hardware.

This checks native functions, NOT device boot or printing. An event queue and
RTOS property calls are replaced with in-memory test services and listed in output.
"""
import argparse
import json
import struct
import sys
import zipfile
from pathlib import Path
from patch_scanner_closed import inspect_container, sha256


def validate(root, package, output):
    sys.path.insert(0,str(root/'python-libs'))
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
        UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
        UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)
    with zipfile.ZipFile(package) as z:
        assert z.testzip() is None
        _,_,ipl,_=inspect_container(z.read(z.namelist()[0]))
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0,0x2000000);u.mem_map(0x40000000,0x4000000)
    u.mem_write(0x10000,ipl[0x3000:])
    for base in [0x40000000,0x41a0d000,0x43e51000]:
        u.mem_write(base,(root/'us/crom-extracted'/f'{base:08x}.bin').read_bytes())
    stop=0x1fff000; sp=0x43fff000
    saved=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
           UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    def call(address,*args):
        for reg,value in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):
            u.reg_write(reg,value)
        for i,r in enumerate(saved):u.reg_write(r,0xabc000+i)
        u.reg_write(UC_ARM_REG_SP,sp);u.reg_write(UC_ARM_REG_LR,stop)
        u.emu_start(address,stop,count=500000)
        assert u.reg_read(UC_ARM_REG_PC)==stop,hex(u.reg_read(UC_ARM_REG_PC))
        assert u.reg_read(UC_ARM_REG_SP)==sp
        assert [u.reg_read(r) for r in saved]==[0xabc000+i for i in range(8)]
        return u.reg_read(UC_ARM_REG_R0)
    caches=[(1,0x40136c70),(2,0x40136cc0),(4,0x40136c98),
            (8,0x40136d10),(16,0x40136ce8),(32,0x40136d60)]
    ports={1:1,2:3,4:2,8:5,16:4,32:7}
    read_cases=0
    for mask,base in caches:
        for fill in range(256):
            for bits in [0x20,0xe0]:
                u.mem_write(base-1,bytes([0xa5])+bytes([fill])*40+bytes([0x5a]))
                assert call(0x48974,ports[mask],bits,base)==0
                b=bytes(u.mem_read(base,40))
                expected=bytearray(40)
                for off,value in [(7,1),(8,5),(9,4),(13,3),(14,3),(33,0x6e)]:
                    expected[off]=value
                assert b==bytes(expected)
                assert bytes(u.mem_read(base-1,1))==b'\xa5'
                assert bytes(u.mem_read(base+40,1))==b'\x5a'
                assert call(0x41a35de0,mask)==1
                read_cases+=1
    # Remove sentinel writes at adjacent cache boundaries by re-reading all slots.
    for mask,base in caches:call(0x48974,ports[mask],0xe0,base)
    assert call(0x41a35e4c)==1
    assert bytes(u.mem_read(0x400c942e,1))==b'\x01'
    # Negative controls: original recognizer must reject incomplete synthetic IDs.
    negatives=0
    for mask,base in caches:
        for off in [7,8,9]:
            old=bytes(u.mem_read(base+off,1));u.mem_write(base+off,b'\0')
            assert call(0x41a35de0,mask)==0
            assert call(0x41a35e4c)==0
            u.mem_write(base+off,old);negatives+=1
    events=[];properties={}
    def ret():u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def external_noop(uc,a,n,x):ret()
    # Exercise the original bitmask/port dispatcher, with bus-idle and scheduler
    # facilities isolated; the candidate reader is executed, not stubbed.
    for a in [0x9fb8c,0x487a0]:
        u.hook_add(UC_HOOK_CODE,external_noop,begin=a,end=a)
    dispatch_cases=0
    for selected in range(64):
        for mask,base in caches:u.mem_write(base,b'\xaa'*40)
        call(0x48b70,selected,0xe0)
        for mask,base in caches:
            b=bytes(u.mem_read(base,40))
            assert b==(bytes(expected) if selected&mask else b'\xaa'*40)
        dispatch_cases+=1
    call(0x48b70,0x3f,0xe0)
    def propget(uc,a,n,x):
        key=uc.reg_read(UC_ARM_REG_R0);ptr=uc.reg_read(UC_ARM_REG_R1);size=uc.reg_read(UC_ARM_REG_R2)
        assert 0<size<=4096
        uc.mem_write(ptr,properties.get(key,b'\0'*size)[:size].ljust(size,b'\0'))
        uc.reg_write(UC_ARM_REG_R0,size);ret()
    def propset(uc,a,n,x):
        key=uc.reg_read(UC_ARM_REG_R0);ptr=uc.reg_read(UC_ARM_REG_R1);size=uc.reg_read(UC_ARM_REG_R2)
        assert 0<size<=4096
        properties[key]=bytes(uc.mem_read(ptr,size));uc.reg_write(UC_ARM_REG_R0,0);ret()
    def event(uc,a,n,x):
        events.append([uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)])
        uc.reg_write(UC_ARM_REG_R0,0);ret()
    # Actual stock functions run; replace only external property/queue facilities.
    for a,f in [(0x65a78,propget),(0x659b8,propset),(0x41a46d90,event)]:
        u.hook_add(UC_HOOK_CODE,f,begin=a,end=a)
    accepted=[];acceptance_cases=0
    for old_state in range(256):
        u.mem_write(0x400c93e0,bytes([old_state])*6)
        for mask,base in caches:
            u.mem_write(0x43ffe000,b'\0')
            result=call(0x41a377b4,mask,0x43ffe000)
            assert result==0,(mask,result)
            assert bytes(u.mem_read(0x43ffe000,1))==b'\0'
            acceptance_cases+=1
            if old_state==0:accepted.append(mask)
        assert bytes(u.mem_read(0x400c93e0,6))==b'\0'*6
    packet=0x43ffd000
    # Stock percentage constructor, then stock six-channel message constructor.
    # Capture the outgoing queue without executing an RTOS scheduler.
    messages=[]
    def alloc(uc,a,n,x):
        uc.mem_write(uc.reg_read(UC_ARM_REG_R1),struct.pack('<I',0x43ffc000))
        uc.reg_write(UC_ARM_REG_R0,0);ret()
    def send(uc,a,n,x):
        ptr=uc.reg_read(UC_ARM_REG_R1)
        messages.append(bytes(uc.mem_read(ptr,32)));uc.reg_write(UC_ARM_REG_R0,0);ret()
    for a,f in [(0x41acad30,alloc),(0x41acc3e0,send)]:
        u.hook_add(UC_HOOK_CODE,f,begin=a,end=a)
    packet_cases=0
    for mode in range(256):
        u.mem_write(packet,b'\xaa'*18);messages.clear()
        call(0x41a40c84,packet,mode)
        data=bytes(u.mem_read(packet,18))
        assert [data[i*3+1] for i in range(6)]==[100]*6,data.hex()
        assert [data[i*3] for i in range(6)]==[0x80]*6,data.hex()
        assert len(messages)==1 and struct.unpack_from('<H',messages[0],8)[0]==0x32
        assert messages[0][12:30]==data
        packet_cases+=1
    report=dict(status='passed',variant='US',package_sha256=sha256(package.read_bytes()),
                synthetic_reader_cases=read_cases,negative_controls=negatives,
                stock_acceptance_masks=accepted,stock_packet_hex=data.hex(),
                stock_read_dispatch_cases=dispatch_cases,
                stock_acceptance_cases=acceptance_cases,stock_packet_mode_cases=packet_cases,
                stock_reported_percentages=[100]*6,stock_channel_status=[0x80]*6,
                stock_all_dummy_recognizer=True,abi_and_write_boundaries_checked=True,
                mocks=['scheduler entry and hardware bus-idle exit for stock read dispatcher',
                       'RTOS property get/set: in-memory, absent keys zero',
                       'event queue sender: records arguments',
                       'message allocation/sending: fixed test buffer'],
                device_tested=False,physical_printing_verified=False)
    output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analysis-root',type=Path,required=True)
    p.add_argument('package',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();validate(a.analysis_root,a.package,a.output)
