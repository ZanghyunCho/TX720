#!/usr/bin/env python3
"""Offline extraction of the supplied L8180 OP09QA CROM resources.

Uses canonical Huffman + LZ reconstructed from donor bootstrap code. Does not
execute the updater or communicate with a printer. Not a firmware patcher.
"""
from pathlib import Path
import argparse,hashlib,json,zipfile

def decode(stream, tokens_path=None):
 if stream[:2]!=b'\xff\xd8':raise ValueError('SOI')
 size=int.from_bytes(stream[2:6],'big');stream=stream[:size]
 p=6;tables={}
 while stream[p:p+2]==b'\xff\xc4':
  end=p+2+int.from_bytes(stream[p+2:p+4],'big');cur=p+4
  while cur<end:
   ident=stream[cur];counts=stream[cur+1:cur+17];syms=stream[cur+17:cur+17+sum(counts)];table=[None]*65536;code=0;idx=0
   for n,count in enumerate(counts,1):
    for _ in range(count):
     if code>=1<<n:raise ValueError('Oversubscribed Huffman table')
     table[code<<(16-n):(code+1)<<(16-n)]=[(syms[idx],n)]*(1<<(16-n));idx+=1;code+=1
    code<<=1
   tables[ident]=table;cur+=17+sum(counts)
  if cur!=end:raise ValueError('DHT length')
  p=end
 if stream[p:p+2]!=b'\xff\xb1':raise ValueError('Scan marker')
 end=p+2+int.from_bytes(stream[p+2:p+4],'big');scan=stream[p+4:end]
 if scan[0]!=3 or scan[10:13]!=bytes.fromhex('001020'):raise ValueError('Unsupported lane selectors')
 huff_size=int.from_bytes(scan[1:5],'big');count=int.from_bytes(scan[5:9],'big');pad=scan[9]
 literal_start=end+huff_size+8;literal=literal_start;raw=stream[end:end+huff_size]
 pos=0;bits=0;buf=0;out=bytearray();sentinels=0;tokens=bytearray()
 def symbol(t):
  nonlocal pos,bits,buf
  while bits<16:
   if pos>=len(raw):raise ValueError('Huffman truncation')
   buf=(buf<<8)|raw[pos];pos+=1;bits+=8
  item=t[(buf>>(bits-16))&65535]
  if item is None:raise ValueError('Invalid Huffman code')
  value,n=item;bits-=n;buf&=(1<<bits)-1;return value
 t0,t1,t2=[tables[k] for k in (0xf0,0xf1,0xf2)]
 for i in range(count):
  length=symbol(t0);distance=symbol(t1)|(symbol(t2)<<8)
  if tokens_path is not None:tokens.extend((length,distance&255,distance>>8))
  if distance:
   n=length+2
   if distance>len(out):raise ValueError(f'Invalid backref at token {i}')
   pattern=out[len(out)-distance:len(out)-distance+min(n,distance)]
   out.extend((pattern*((n+len(pattern)-1)//len(pattern)))[:n])
  elif length==255:sentinels+=1
  else:
   n=length+1
   if literal+n>size:raise ValueError('Literal overrun')
   out.extend(stream[literal:literal+n]);literal+=n
  if len(out)>0x8000000:raise ValueError('Output limit')
 if literal!=size:raise ValueError(f'Literal mismatch {literal} != {size}')
 if tokens_path is not None:tokens_path.write_bytes(tokens)
 return bytes(out),dict(compressed_size=size,huffman_offset=end,huffman_size=huff_size,huffman_read_bytes=pos,token_count=count,padding=pad,literal_offset=literal_start,literal_size=size-literal_start,sentinels=sentinels)


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('efu',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
 expected='2973accac530f01e9fe09ace5ef8c0034ae4f27dc5e12becf26abab050492a04'
 if hashlib.sha256(a.efu.read_bytes()).hexdigest()!=expected:raise ValueError('Only exact supplied FWCJ21TL.efu is supported')
 if a.output.exists():raise ValueError('Refusing to overwrite output directory')
 with zipfile.ZipFile(a.efu) as z:
  if z.testzip() is not None or z.namelist()!=['FWCJ21TL.rcx']:raise ValueError('Container mismatch')
  rcx=z.read(z.namelist()[0])
 if rcx[301:302]!=b'\x0c' or rcx[302:311]!=b'EPSONSIGN':raise ValueError('Payload mismatch')
 b=rcx[302:];a.output.mkdir(parents=True);records=[]
 for offset in [0xb4000,0xf17010,0x1efa010,0x1f3c010,0x1fdc010]:
  pos=offset+4;index=0
  if b[offset:pos]!=b'CROM':raise ValueError('CROM marker mismatch')
  while b[pos:pos+2]==b'\xff\xd8':
   data,meta=decode(b[pos:]);name=f'{offset:08x}-{index}.bin';(a.output/name).write_bytes(data)
   meta.update(container_offset=hex(offset),stream_offset=hex(pos),index=index,file=name,decoded_size=len(data),sha256=hashlib.sha256(data).hexdigest())
   records.append(meta);print(json.dumps(meta),flush=True);pos+=meta['compressed_size'];index+=1
 if len(records)!=8:raise ValueError('Expected eight decoded segments')
 (a.output/'manifest.json').write_text(json.dumps(records,indent=2)+'\n')

if __name__=='__main__':main()
