#!/usr/bin/env python3
"""Run the v2 status wrapper, original API serializer and original ink error logic.

No printer access. Kernel queue/identity services and final error/notification
sinks are mocked. The wrapper, original message copy and error decisions execute
as ARM instructions from the package and original CROM.
"""
import argparse
import json
import struct
import sys
import zipfile
from pathlib import Path
from patch_scanner_closed import inspect_container, sha256
from patch_us_chipless_candidate import STATUS_API, FILTER_ADDRESS, STATUS_FILTER, arm_branch, LEVEL_GETTER, FULL_LEVEL


def validate(root,package,output):
    sys.path.insert(0,str(root/'python-libs'))
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ
    from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,
        UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)
    with zipfile.ZipFile(package) as z:
        assert z.testzip() is None
        _,_,ipl,_=inspect_container(z.read(z.namelist()[0]))
    assert ipl[STATUS_API-0xd000:STATUS_API-0xd000+4]==struct.pack('<I',arm_branch(STATUS_API,FILTER_ADDRESS))
    assert ipl[FILTER_ADDRESS-0xd000:FILTER_ADDRESS-0xd000+len(STATUS_FILTER)]==STATUS_FILTER
    assert ipl[LEVEL_GETTER-0xd000:LEVEL_GETTER-0xd000+8]==FULL_LEVEL
    # The filter reuses the old reader's tail. Reject external aligned direct
    # branches or absolute pointers into that tail in original ROM/CROM blocks.
    original=(root/'us/part1.ipl').read_bytes()
    assert sha256(original)=='6fa67ff99fba51882772fa15164800129c70f9fa2518e3a869e1f367b45f81d4'
    sources=[(0x10000,original[0x3000:],True)]
    for base in [0x40000000,0x41a0d000,0x43e51000]:
        sources.append((base,(root/'us/crom-extracted'/f'{base:08x}.bin').read_bytes(),base==0x41a0d000))
    external=[]
    for base,data,executable in sources:
        for off in range(0,len(data)-3,4):
            word=struct.unpack_from('<I',data,off)[0];address=base+off
            if FILTER_ADDRESS<=word<FILTER_ADDRESS+len(STATUS_FILTER):
                external.append(['pointer',hex(address),hex(word)])
            if executable and word&0x0e000000==0x0a000000:
                displacement=word&0xffffff
                if displacement&0x800000:displacement-=0x1000000
                target=address+8+displacement*4
                if FILTER_ADDRESS<=target<FILTER_ADDRESS+len(STATUS_FILTER) and not 0x48974<=address<0x48a48:
                    external.append(['branch',hex(address),hex(target)])
    assert external==[],external
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.mem_map(0,0x2000000);u.mem_map(0x40000000,0x4000000)
    u.mem_map(0x45000000,0x1000,UC_PROT_READ)
    u.mem_write(0x10000,ipl[0x3000:])
    for base in [0x40000000,0x41a0d000,0x43e51000]:
        u.mem_write(base,(root/'us/crom-extracted'/f'{base:08x}.bin').read_bytes())
    regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
          UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    stop=0x1fff000;sp=0x43fff000;message=0x43ffc000
    sent=[];flags={};errorbits={};properties={}
    def ret(value=None):
        if value is not None:u.reg_write(UC_ARM_REG_R0,value)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def identity(uc,a,n,x):
        uc.mem_write(uc.reg_read(UC_ARM_REG_R0),struct.pack('<H',9));ret(0)
    def alloc(uc,a,n,x):
        uc.mem_write(message,b'\0'*256)
        uc.mem_write(uc.reg_read(UC_ARM_REG_R1),struct.pack('<I',message));ret(0)
    def send(uc,a,n,x):
        assert uc.reg_read(UC_ARM_REG_R0)==0x8e
        sent.append(bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1),128)));ret(0)
    def flag(uc,a,n,x):
        flags[uc.reg_read(UC_ARM_REG_R0)]=uc.reg_read(UC_ARM_REG_R1);ret(0)
    def errorbit(uc,a,n,x):
        errorbits[uc.reg_read(UC_ARM_REG_R0)]=uc.reg_read(UC_ARM_REG_R1);ret(0)
    def noop(uc,a,n,x):ret(0)
    def getprop(uc,a,n,x):
        key=uc.reg_read(UC_ARM_REG_R0);ptr=uc.reg_read(UC_ARM_REG_R1);size=uc.reg_read(UC_ARM_REG_R2)
        assert 0<size<=4096
        uc.mem_write(ptr,properties.get(key,b'\0'*size)[:size].ljust(size,b'\0'));ret(size)
    def setprop(uc,a,n,x):
        key=uc.reg_read(UC_ARM_REG_R0);ptr=uc.reg_read(UC_ARM_REG_R1);size=uc.reg_read(UC_ARM_REG_R2)
        assert 0<size<=4096
        properties[key]=bytes(uc.mem_read(ptr,size));ret(0)
    mocks={0x3742f4:identity,0x374304:alloc,0x37430c:send,
           0x41ad34bc:flag,0x41ad433c:errorbit,0x41ad2fcc:noop,
           0x41ad33cc:noop,0x41ad31a8:noop,0x41ad2d34:noop,
           0x167a8:noop,0x17eb0c:noop,0x65a78:getprop,0x659b8:setprop}
    for a,f in mocks.items():u.hook_add(UC_HOOK_CODE,f,begin=a,end=a)
    def call(a,*args):
        for reg,value in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2],args):u.reg_write(reg,value)
        for i,reg in enumerate(regs):u.reg_write(reg,0xabc000+i)
        u.reg_write(UC_ARM_REG_SP,sp);u.reg_write(UC_ARM_REG_LR,stop)
        u.emu_start(a,stop,count=200000)
        assert u.reg_read(UC_ARM_REG_PC)==stop,hex(u.reg_read(UC_ARM_REG_PC))
        assert u.reg_read(UC_ARM_REG_SP)==sp
        assert [u.reg_read(r) for r in regs]==[0xabc000+i for i in range(8)]
        return u.reg_read(UC_ARM_REG_R0)
    def transmit(key,data,readonly=False):
        ptr=0x45000010 if readonly else 0x43ffd010
        guard=b'\xa5'*16+data+b'\x5a'*16
        u.mem_write(ptr-16,guard);sent.clear()
        call(STATUS_API,key,ptr,len(data))
        assert bytes(u.mem_read(ptr-16,len(guard)))==guard
        assert len(sent)==1
        p=sent[0]
        assert struct.unpack_from('<HHH',p,4)==(9,0x8e,2)
        assert struct.unpack_from('<I',p,12)[0]==key
        return p[16:16+len(data)]
    level_cases=0
    for cached in range(256):
        u.mem_write(0x400d5dbf,bytes([cached])*6)
        for slot in range(6):
            assert call(LEVEL_GETTER,slot)==100
            level_cases+=1
    count=0
    for old in range(256):
        for readonly in [False,True]:
            for key,size,value in [(0x15,6,100),(0x16,6,1)]+[(k,1,1) for k in range(0x211,0x217)]:
                assert transmit(key,bytes([old])*size,readonly)==bytes([value])*size
                count+=1
    untouched=0
    for key in [0,1,0xc,0x14,0x17,0x25,0x200,0x201,0x210,0x217,0x218,0x430,0x448,0x800]:
        for size in [1,2,6,8,32,64]:
            data=bytes((i*17+key)&255 for i in range(size))
            assert transmit(key,data)==data
            untouched+=1
    for key in [0x15,0x16]+list(range(0x211,0x217)):
        for size in [1,2,6,8]:
            expected_size=6 if key<0x200 else 1
            if size!=expected_size:
                data=bytes(range(size));assert transmit(key,data)==data;untouched+=1
    # Original receiver's storage functions, then original decision function.
    # Begin with six recognized/non-empty slots; inject one rejected or empty slot.
    aux=0x400d2d70;end=0x400d2d64
    def apply(key,data):
        p=bytearray(128);struct.pack_into('<I',p,12,key);p[16:16+len(data)]=data
        u.mem_write(message,bytes(p))
        call(0x41ad4028 if key==0x16 else 0x41ad3a4c,message)
        flags.clear();errorbits.clear();call(0x41ad4384,message)
        return {str(k):v for k,v in flags.items() if v}, {hex(k):v for k,v in errorbits.items() if v}
    integration=[]
    for slot in range(6):
        for code in [2,3,4,5]:
            key=0x211+slot
            u.mem_write(aux,b'\x01'*6);u.mem_write(end,b'\x01'*6)
            before=apply(key,bytes([code]))
            assert before[0],(slot,code,before)
            u.mem_write(aux,b'\x01'*6);u.mem_write(end,b'\x01'*6)
            normalized=transmit(key,bytes([code]))
            after=apply(key,normalized)
            assert not after[0] and not after[1],(slot,code,after)
            integration.append(dict(slot=slot,input_code=code,before=before,after=after))
        data=bytearray(b'\x01'*6);data[slot]=3
        u.mem_write(aux,b'\x01'*6);u.mem_write(end,b'\x01'*6)
        before=apply(0x16,data);assert before[0]
        u.mem_write(aux,b'\x01'*6);u.mem_write(end,b'\x01'*6)
        normalized=transmit(0x16,data);after=apply(0x16,normalized)
        assert not after[0] and not after[1],(slot,after)
        integration.append(dict(slot=slot,input='end-status-3',before=before,after=after))
    # A real unrelated error still reaches the original error decision and bit sink.
    data=transmit(0xc,b'\x01');u.mem_write(aux,b'\x01'*6);u.mem_write(end,b'\x01'*6)
    unrelated=apply(0xc,data)
    assert unrelated[1].get('0x8')==1,unrelated
    report=dict(status='passed',revision=2,package_sha256=sha256(package.read_bytes()),
                gui_level_getter_cases=level_cases,
                original_rom_crom_external_direct_references_to_reused_tail=external,
                normalized_api_cases=count,unmodified_message_cases=untouched,
                native_error_decision_cases=integration,unrelated_error_preserved=unrelated,
                abi_and_readonly_caller_data_checked=True,
                mocks=[hex(a) for a in mocks],
                scope='Actual wrapper, original API serializer/copy, original status stores and ink error decisions. Kernel, flag sinks and final notifications mocked. No full device emulation.',
                device_tested=False,printing_verified=False)
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {count} normalized API cases, {untouched} unchanged cases, {len(integration)} native error comparisons; unrelated error retained.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analysis-root',type=Path,required=True);p.add_argument('package',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    validate(a.analysis_root,a.package,a.output)
