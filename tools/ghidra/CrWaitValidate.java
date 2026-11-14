import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.io.*;
public class CrWaitValidate extends GhidraScript {
 long call(long entry,int heat,int scale,boolean pf) throws Exception {
  EmulatorHelper e=new EmulatorHelper(currentProgram); try {
   long state=pf?0x400b6a3cL:0x400b6564L;
   byte[] hb=new byte[4],sb=new byte[4];for(int i=0;i<4;i++){hb[i]=(byte)(heat>>(8*i));sb[i]=(byte)(scale>>(8*i));}
   e.writeMemory(toAddr(state+0x14),hb);e.writeMemory(toAddr(state+0x20),sb);
   e.writeRegister("PS",0x25);e.writeRegister("SAR",0);e.writeRegister("pc",entry);e.writeRegister("a0",0x8001fff0L);e.writeRegister("a1",0x80020ff0L);
   for(int i=12;i<16;i++)e.writeRegister("a"+i,0xabc000L+i);
   int n=0;while(e.getExecutionAddress().getOffset()!=0x8001fff0L&&n++<2000){if(!e.step(monitor))throw new Exception("Emulation failed: "+e.getLastError()+" pc="+e.getExecutionAddress());}
   if(n>=2000)throw new Exception("Instruction budget exceeded");
   if(e.readRegister("a1").longValue()!=0x80020ff0L)throw new Exception("SP changed");
   for(int i=12;i<16;i++)if(e.readRegister("a"+i).longValue()!=0xabc000L+i)throw new Exception("Saved register changed");
   return e.readRegister("a2").longValue()&0xffffffffL;
  } finally {e.dispose();}
 }
 int expected(int h,int s,boolean pf){
  int t0=pf?222830:229989,t1=pf?233450:240941,t2=pf?239810:247512,v;
  if(h<t0)v=0;
  else if(h<t1)v=((pf?1664:3072)*(h-t0))>>18;
  else if(h<t2)v=(pf?64:128)+(((pf?17152:6144)*(h-t1))>>(pf?17:18));
  else v=(pf?896:282)+(((pf?17792:24576)*(h-t2))>>16);
  v=(s*v)>>7;return (short)Math.min(v,32767);
 }
 public void run() throws Exception {
  byte[] image=getBytes(toAddr(0x40000000L),0xbb544);
  String hash=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(image));
  if(!hash.equals("955e434a779e4c2fa516c226af004419602fb7d4f0395043582377dbba88f3c3"))throw new Exception("Unexpected source image hash: "+hash);
  if(currentProgram.getMemory().getBlock(toAddr(0x80010000L))==null){
   byte[] runtime=getBytes(toAddr(0x400b64c4L),0x5080);
   var block=currentProgram.getMemory().createInitializedBlock("core2_runtime",toAddr(0x80010000L),new ByteArrayInputStream(runtime),runtime.length,monitor,false);
   block.setRead(true);block.setWrite(false);block.setExecute(true);
  }
  if(currentProgram.getMemory().getBlock(toAddr(0x80020000L))==null)currentProgram.getMemory().createInitializedBlock("emulation_stack",toAddr(0x80020000L),0x1000,(byte)0,monitor,false);
  long cr=0x400aaa78L,pf=0x400aea08L;
  byte[] original=getBytes(toAddr(cr),4);if(!java.util.Arrays.equals(original,new byte[]{0x21,0x3c,0,0x31}))throw new Exception("Unexpected CR entry bytes");
  disassemble(toAddr(cr));disassemble(toAddr(pf));
  int[] hs={0,222829,222830,229988,229989,233449,233450,239809,239810,240940,240941,247511,247512,250000,300000};int[] ss={64,128,256};int count=0;
  try(PrintWriter out=new PrintWriter(getScriptArgs().length>0?getScriptArgs()[0]:"cr-wait-query-validation.json")){
   for(boolean p:new boolean[]{false,true})for(int h:hs)for(int s:ss){long got=call(p?pf:cr,h,s,p);long want=Integer.toUnsignedLong(expected(h,s,p));if(got!=want)throw new Exception("Original model mismatch "+p+" "+h+" "+s+" got="+got+" wanted="+want);count++;}
   clearListing(toAddr(cr),toAddr(cr+5));setBytes(toAddr(cr),new byte[]{0x0c,0x02,0x0d,(byte)0xf0});disassemble(toAddr(cr));
   if(!getInstructionAt(toAddr(cr)).toString().equals("movi.n a2,0x0"))throw new Exception("Unexpected patched instruction "+getInstructionAt(toAddr(cr)));
   if(!getInstructionAt(toAddr(cr+2)).getMnemonicString().equals("ret.n"))throw new Exception("Expected ret.n");
   for(int h:hs)for(int s:ss){if(call(cr,h,s,false)!=0)throw new Exception("CR bypass failed");if(call(pf,h,s,true)!=Integer.toUnsignedLong(expected(h,s,true)))throw new Exception("PF changed");count+=2;}
   out.println("{\"status\":\"passed\",\"query_cases\":"+count+",\"cr_only_returns_zero\":true,\"pf_model_preserved\":true,\"stack_and_saved_registers_preserved\":true,\"method\":\"Ghidra Xtensa p-code emulation with fixed core-2 extended L32R pool\",\"physical_device_tested\":false}");
  }finally{clearListing(toAddr(cr),toAddr(cr+5));setBytes(toAddr(cr),original);disassemble(toAddr(cr));}
 }
}
