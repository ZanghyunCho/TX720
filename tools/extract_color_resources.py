#!/usr/bin/env python3
"""Use the original TX720 ARM resource codec and EP355 postprocessor offline.

Requires original US analysis images and extracted L8180 000b4000-0.bin.
Heap/handle allocation is modeled; no firmware updater or printer is accessed.
Outputs are analysis resources, not flashable firmware or validated color data.
"""
from pathlib import Path
import struct,sys,json,hashlib
import argparse
p=argparse.ArgumentParser(description='Extract compressed EP color resources using original TX720 ARM codec. No device access; allocator boundaries are mocked.')
p.add_argument('--analysis-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
r=args.analysis_root
sys.path.insert(0,str(r/"python-libs"))
from unicorn import *
from unicorn.arm_const import *
if args.output.exists():raise ValueError('Refusing to overwrite output directory')
checks={
 r/'us/part1.ipl':'6fa67ff99fba51882772fa15164800129c70f9fa2518e3a869e1f367b45f81d4',
 r/'us/part2.ipl':'4186177f1d6941da6ab642fe962e6b3d51761d9d7026c777e5003472785b7ef0',
 r/'us/crom-extracted/41a0d000.bin':'a5111316243e44acb55395dc99766b679ccb572d29990d8ac10de3dc2e66c275',
 r/'l8180/crom-extracted/000b4000-0.bin':'418df34d081aab1eca5f266db9283dc9cd87672a4ee50175a0a6dbc9ccb49bd3'}
for path,wanted in checks.items():
 if hashlib.sha256(path.read_bytes()).hexdigest()!=wanted:raise ValueError(f'Unexpected input image: {path}')
args.output.mkdir(parents=True)
u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0,0x2000000);u.mem_map(0x40000000,0x4000000)
p1=(r/'us/part1.ipl').read_bytes()[0x3000:];p2=(r/'us/part2.ipl').read_bytes()[0x3000:]
u.mem_write(0x10000,p1);u.mem_write(0x1000000,p2)
for base in [0x41a0d000,0x40000000,0x43e51000]:u.mem_write(base,(r/'us/crom-extracted'/f'{base:08x}.bin').read_bytes())
heap_next=0x43200000
def alloc(uc,a,n,x):
 global heap_next
 size=uc.reg_read(UC_ARM_REG_R0);ptr=heap_next;heap_next+=(size+63)&~63
 assert heap_next<0x43d00000
 uc.mem_write(ptr,b'\0'*size);uc.reg_write(UC_ARM_REG_R0,ptr);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
def lock(uc,a,n,x):uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
def release(uc,a,n,x):uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
for addr,fn in [(0x41b490c4,alloc),(0x41b490cc,lock),(0x41b490a4,release),(0x41b490ac,release)]:u.hook_add(UC_HOOK_CODE,fn,begin=addr,end=addr)
sig=bytes.fromhex('7acf865c7d903c')
sets=[('tx720',p1),('l8180',(r/'l8180/crom-extracted/000b4000-0.bin').read_bytes())]
for label,src in sets:
 out=args.output/label;out.mkdir();rows=[];pos=0
 while True:
  pos=src.find(sig,pos)
  if pos<0:break
  a=pos;pos+=1
  if a+16>len(src) or src[a+7] not in (0xb9,0xba):continue
  size,n=struct.unpack_from('<II',src,a+8)
  if not (16<=size<=len(src)-a and 0<n<0x1000000):continue
  blob=src[a:a+size];u.mem_write(0x43000000,blob)
  for reg,val in [(UC_ARM_REG_R0,0x4300000c),(UC_ARM_REG_R1,size),(UC_ARM_REG_R2,0x42100000),(UC_ARM_REG_R3,n),(UC_ARM_REG_SP,0x43fff000),(UC_ARM_REG_LR,0x1fff000)]:u.reg_write(reg,val)
  u.mem_write(0x43fff000,struct.pack('<I',0x42000000))
  u.emu_start(0x41b2daf4,0x1fff000,count=30000000)
  assert u.reg_read(UC_ARM_REG_PC)==0x1fff000 and u.reg_read(UC_ARM_REG_R0)==n,(label,hex(a),n,u.reg_read(UC_ARM_REG_R0))
  if src[a+7]==0xba:
   heap_next=0x43200000
   for reg,val in [(UC_ARM_REG_R0,0x42100000),(UC_ARM_REG_R1,n),(UC_ARM_REG_SP,0x43fff000),(UC_ARM_REG_LR,0x1fff000)]:u.reg_write(reg,val)
   try:u.emu_start(0x41b2d44c,0x1fff000,count=30000000)
   except UcError as e:
    print('postprocess error',label,hex(a),e,'PC',hex(u.reg_read(UC_ARM_REG_PC)),flush=True);raise
   assert u.reg_read(UC_ARM_REG_PC)==0x1fff000 and u.reg_read(UC_ARM_REG_R0)==0
  d=bytes(u.mem_read(0x42100000,n));name=f'{a:08x}.bin';(out/name).write_bytes(d)
  row=dict(offset=hex(a),compressed_size=size,decoded_size=n,kind=hex(src[a+7]),file=name,sha256=hashlib.sha256(d).hexdigest())
  rows.append(row)
 (out/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(label,'resources',len(rows),'bytes',sum(x['decoded_size'] for x in rows),flush=True)
