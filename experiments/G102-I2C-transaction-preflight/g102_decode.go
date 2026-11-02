package main

import (
 "encoding/binary"
 "errors"
 "fmt"
)

var le = binary.LittleEndian
const captureBytes = 8832
var bases = [2]uint32{0x880000,0x98c000}
var wrappers = [2]uint32{0x8c0000,0x9c0000}
var roots = [2]uint32{0x11e010,0x11705c}
var offsets = []uint32{0,4,0x24,0x28,0x40,0x48,0x4c,0x64,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0x800,0x804,0xe24,0xe28,0x258,0x7c,0x254,0x260,0x264,0x284,0x288,0x600,0x604,0x614,0x630,0x634,0x644,0x80c,0x810,0x814,0x908}
var registers = []string{"init_revision","secondary_init_revision","output_control","clock_gating","status","main_clock_config","secondary_clock_config","interface_disable","main_firmware","secondary_firmware","TX_length","RX_length","SCL_counters","main_IRQ_status","secondary_IRQ_status","TX_FIFO_status","RX_FIFO_status","hardware_parameter0","hardware_parameter1","DMA_mode","clock_selection","byte_granularity","TX_packing0","TX_packing1","RX_packing0","RX_packing1","main_command_history","main_command_control","main_IRQ_enable","secondary_command_history","secondary_command_control","secondary_IRQ_enable","TX_watermark","RX_watermark","RX_RFR_watermark","IO_lines"}
var clockAddresses = [2][6]uint32{{0x152010,0x11e004,0x152010,0x1233cc,0x152010,0x1233d0},{0x152008,0x117058,0x152008,0x123144,0x152008,0x123140}}
var pins = [4]uint32{0,1,22,23}
func controllerOffset(i,j int) uint32 {if i==1&&j==17{return 0x50};if i==1&&j==18{return 0xffffffff};return offsets[j]}
func allowed(at uint32) (bool,bool) {
 for i:=0;i<2;i++ {
  if i==0&&at==wrappers[i]+4{return true,true}
  for j:=range offsets{v:=controllerOffset(i,j);if v!=0xffffffff&&at==bases[i]+v{return true,true}}
  if at==roots[i]||at==roots[i]+4{return true,false}
  for _,v:=range clockAddresses[i]{if at==v{return true,false}}
 }
 for _,pin:=range pins{base:=uint32(0xf100000)+pin*0x1000;if at==base||at==base+4{return true,false}}
 return false,false
}
func decodeStatus(b []byte)(map[string]any,error){
 if len(b)!=80||le.Uint32(b)!=80||le.Uint32(b[4:])!=1||string(b[8:16])!="OG102RD1"{return nil,errors.New("G102 status ABI")}
 v:=map[string]any{}
 for i,n:=range []string{"kernel_build","processors","IRQL","firmware_bytes","firmware_match","firmware_status","map_calls","attempts","ready","fault"}{v[n]=le.Uint32(b[16+4*i:])}
 for i,n:=range []string{"interrupt_time","frequency","sequence"}{v[n]=le.Uint64(b[56+8*i:])}
 return v,nil
}
func decodeCapture(b []byte,nonce uint64)(map[string]any,error){
 if len(b)!=captureBytes{return nil,errors.New("G102 capture size")}
 s,e:=decodeStatus(b[:80]);if e!=nil{return nil,e};if le.Uint64(b[80:])!=nonce{return nil,errors.New("frozen nonce")}
 u:=func(at int)uint32{return le.Uint32(b[104+at:])};q:=func(at int)uint64{return le.Uint64(b[104+at:])}
 nr,maps,guard:=le.Uint32(b[88:]),le.Uint32(b[92:]),le.Uint32(b[96:]);code,reads,n,ready:=u(4),u(12),u(16),u(20)
 if u(0)!=8728||(code>6&&code!=1004)||reads>1024||n>reads||nr<reads||nr>2048||maps>11||guard>2||le.Uint32(b[100:])!=0||ready>3||u(24)>3||u(28)>15{return nil,errors.New("G102 capture bounds")}
 peripheral:=uint32(0);peripheralValues:=map[uint32]uint32{}
 for i:=0;i<int(n);i++{at:=le.Uint32(b[640+8*i:]);ok,p:=allowed(at);if !ok{return nil,fmt.Errorf("unqualified trace address %x",at)};if p{peripheral++;if _,exists:=peripheralValues[at];exists&&code==0{return nil,errors.New("duplicate peripheral field")};peripheralValues[at]=le.Uint32(b[644+8*i:])}}
 controllers:=[]map[string]any{}
 for i:=0;i<2;i++ {
  before,after:=[]string{},[]string{}
  for j:=0;j<8;j++{before=append(before,fmt.Sprintf("0x%08x",u(48+32*i+4*j)));after=append(after,fmt.Sprintf("0x%08x",u(112+32*i+4*j)))}
  row:=map[string]any{"base":fmt.Sprintf("0x%x",bases[i]),"clock_snapshot_before":before,"clock_snapshot_after":after,"clock_admitted":ready&(1<<i)!=0}
  if ready&(1<<i)!=0 {
   values:=map[string]string{};complete:=true;for j,name:=range registers{offset:=controllerOffset(i,j);if offset==0xffffffff{continue};if i==1&&j==17{name="hub_hardware_parameter"};value:=u(240+144*i+4*j);values[name]=fmt.Sprintf("0x%08x",value);observed,ok:=peripheralValues[bases[i]+offset];if !ok||observed!=value{complete=false}};if i==0{wrapper,ok:=peripheralValues[wrappers[i]+4];if !ok||wrapper!=u(528+4*i){complete=false}};row["register_snapshot_complete"]=complete;if code==0&&!complete{return nil,errors.New("peripheral arrays disagree with trace")}
   row["registers"]=values;if i==0{row["wrapper_version"]=fmt.Sprintf("0x%08x",u(528+4*i))}else{row["skipped_by_source_contract"]=[]string{"ordinary_QUP_wrapper_version","ordinary_FIFO_parameter1"}};row["protocol"]=(u(240+144*i+4*8)>>8)&255;row["FIFO_interface_disabled"]=u(240+144*i+4*7)&1!=0
  }
  controllers=append(controllers,row)
 }
 pinRows:=[]map[string]any{}
 for i,pin:=range pins{cfg,input:=u(176+8*i),u(176+8*i+4);pinRows=append(pinRows,map[string]any{"GPIO":pin,"configuration_before":fmt.Sprintf("0x%08x",cfg),"configuration_after":fmt.Sprintf("0x%08x",u(208+8*i)),"input_before":input&1,"input_after":u(208+8*i+4)&1,"mux":(cfg>>2)&15})}
 if code==0{
  expectedMaps,expectedPeriph:=uint32(8),uint32(0);if ready&1!=0{expectedMaps+=2;expectedPeriph+=37};if ready&2!=0{expectedMaps++;expectedPeriph+=35}
  if s["kernel_build"]!=uint32(26300)||s["processors"]!=uint32(8)||s["IRQL"]!=uint32(0)||s["firmware_bytes"]!=uint32(576)||s["firmware_match"]!=uint32(1)||s["firmware_status"]!=uint32(0)||s["attempts"]!=uint32(1)||s["ready"]!=uint32(1)||s["fault"]!=uint32(0)||s["map_calls"]!=maps||maps!=expectedMaps||peripheral!=expectedPeriph||nr!=reads+8*peripheral||reads!=n||guard!=0||q(40)<q(32)||q(40)-q(32)>2000000{return nil,errors.New("G102 success invariants")}
 }
 return map[string]any{"status":s,"operation_code":code,"stage":u(8),"reads":reads,"native_reads":nr,"map_calls":maps,"guard":guard,"trace_entries":n,"ready_mask":ready,"clock_words_unchanged_mask":u(24),"pin_words_unchanged_mask":u(28),"begin_us":q(32),"end_us":q(40),"controllers":controllers,"pins":pinRows,"hardware_write_commands":0,"I2C_transactions_issued":0,"gauge_identity_qualified":false},nil
}
