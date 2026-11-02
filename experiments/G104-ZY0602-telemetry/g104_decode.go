package main
import("encoding/binary";"fmt";"errors")
var le=binary.LittleEndian
const captureBytes=279880
var bases=[2]uint32{0x880000,0x98c000}
func kind(n uint32)uint32{n%=23;if n<9{return n%3};return 1+((n-9)&1)}
func payload(n uint32)uint32{n%=23;if n<9{if n%3==0{return (n/3)<<8};return 0};return []uint32{6,8,10,16,18,20,44}[(n-9)/2]}
var offsets=[]uint32{0,4,0x24,0x28,0x40,0x48,0x4c,0x64,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0x800,0x804,0xe24,0xe28,0x258,0x7c,0x254,0x260,0x264,0x284,0x288,0x600,0x604,0x614,0x630,0x634,0x644,0x80c,0x810,0x814,0x908}
func allowed(at uint32)bool{
 for i,base:=range bases{for j,o:=range offsets{if i==1&&j==17{o=0x50};if i==1&&j==18{continue};if at==base+o{return true}};if at==base+0x780{return true}}
 return false
}
func decodeStatus(b []byte)(map[string]any,error){
 if len(b)!=80||le.Uint32(b)!=80||le.Uint32(b[4:])!=1||string(b[8:16])!="OG104TL1"{return nil,errors.New("G104 status ABI")}
 v:=map[string]any{};for i,n:=range []string{"kernel_build","processors","IRQL","firmware_bytes","firmware_match","firmware_status","map_calls","attempts","ready","fault"}{v[n]=le.Uint32(b[16+4*i:])};for i,n:=range []string{"interrupt_time","frequency","sequence"}{v[n]=le.Uint64(b[56+8*i:])};return v,nil
}
func probe(b []byte,optional bool)(map[string]any,error){
 if len(b)!=8728{return nil,errors.New("probe size")};if optional&&le.Uint32(b)==0{for _,v:=range b{if v!=0{return nil,errors.New("partial missing probe")}};return map[string]any{"not_run":true},nil};if le.Uint32(b)!=8728{return nil,errors.New("probe size")};u:=func(o int)uint32{return le.Uint32(b[o:])}
 if u(4)>6||u(12)>1024||u(16)>u(12)||u(20)>3||u(24)>3||u(28)>15{return nil,errors.New("probe bounds")}
 if u(4)==0&&(u(12)!=696||u(16)!=696||u(20)!=3||u(24)!=3||u(28)!=15){return nil,errors.New("probe complete bounds")}
 return map[string]any{"code":u(4),"reads":u(12),"ready_mask":u(20),"clock_words_unchanged_mask":u(24),"pin_words_unchanged_mask":u(28)},nil
}
func decodeCapture(b []byte,nonce uint64)(map[string]any,error){
 if len(b)!=captureBytes{return nil,errors.New("capture size")};s,e:=decodeStatus(b[:80]);if e!=nil{return nil,e};if le.Uint64(b[80:])!=nonce{return nil,errors.New("nonce")}
 r:=b[120:];u:=func(o int)uint32{return le.Uint32(r[o:])};q:=func(o int)uint64{return le.Uint64(r[o:])}
 nr,nw,maps,guard,pc,pd,pf:=le.Uint32(b[88:]),le.Uint32(b[92:]),le.Uint32(b[96:]),le.Uint32(b[100:]),le.Uint32(b[104:]),le.Uint32(b[108:]),le.Uint32(b[112:])
 code,n,reads,writes:=u(4),u(32),u(40),u(44)
 if u(0)!=279760||(code>12&&code!=1004)||u(12)>46||u(16)>u(12)||u(20)>0xfffff||u(24)>3||u(28)>3||n>16384||u(36)!=0||reads>16384||writes>512||u(48)>46||u(52)>46||u(56)>3||u(60)>1||nr>200000||nw>512||maps>11||guard>4||pc>46||pd>pc||pf>1||le.Uint32(b[116:])!=0{return nil,errors.New("capture bounds")}
 readEvents,writeEvents,cmdEvents,fifoEvents,rxEvents:=uint32(0),uint32(0),uint32(0),uint32(0),uint32(0)
 for i:=uint32(0);i<n;i++{
  at:=17616+int(i)*16;k,a,v,cmd:=le.Uint32(r[at:]),le.Uint32(r[at+4:]),le.Uint32(r[at+8:]),le.Uint32(r[at+12:]);if cmd>46{return nil,errors.New("trace command")}
  if k==1{if !allowed(a){return nil,errors.New("read trace address")};if a&4095==0x780{if rxEvents>=20||a!=bases[rxEvents/10]+0x780||(code==0&&v&65535!=u(80+int(rxEvents)*4)){return nil,errors.New("raw word/trace disagreement")};rxEvents++};readEvents++}else if k==2{
   base:=uint32(0);for _,x:=range bases{if a>=x&&a-x<4096{base=x}};if base==0{return nil,errors.New("write trace base")}
   switch a-base{
   case 0x26c:if v!=1&&v!=3{return nil,errors.New("TX length")}
   case 0x270:if v!=2{return nil,errors.New("RX length")}
   case 0x80c:if v>1{return nil,errors.New("watermark")}
   case 0x600:if cmdEvents>=46||a!=bases[cmdEvents/23]+0x600||v!=[]uint32{0x0800aa00,0x0800aa04,0x1000aa00}[kind(cmdEvents)]{return nil,errors.New("fixed command")};cmdEvents++
   case 0x700:if cmdEvents==0||v!=payload(cmdEvents-1){return nil,errors.New("fixed register selection")};fifoEvents++
   case 0x604:if v!=4&&v!=2{return nil,errors.New("cancel/abort")}
   case 0x618:if v==0||v&^uint32(0x7fc07e7f)!=0{return nil,errors.New("owned IRQ clear")}
   default:return nil,errors.New("write trace offset")
   };writeEvents++
  }else{return nil,errors.New("trace kind")}
 }
 if readEvents>reads||writeEvents>writes||cmdEvents>u(12)||nw!=writeEvents||(code==0&&(reads!=readEvents||writes!=writeEvents||u(12)!=cmdEvents)){return nil,errors.New("trace counters")}
 before,e:=probe(r[160:8888],code==1004);if e!=nil{return nil,e};after,e:=probe(r[8888:17616],code==1004||u(56)!=0);if e!=nil{return nil,e}
 rows:=[]map[string]any{}
 for i,base:=range bases{
  words:=make([]uint32,10);for j:=range words{words[j]=u(80+40*i+4*j);if words[j]>65535{return nil,errors.New("query word")}}
  status,id,fw:=words[0],words[1],words[2];complete:=(u(20)>>(10*i))&1023==1023
  current:=int32(int16(words[8]));plausible:=complete&&id==0x0602&&words[9]<=100&&words[3]>=2000&&words[3]<=4000&&words[4]>=1000&&words[4]<=6000&&words[7]>0&&words[6]<=words[7]
  rows=append(rows,map[string]any{"controller":fmt.Sprintf("0x%x",base),"address":"0x55","control_status":fmt.Sprintf("0x%04x",status),"device_type":fmt.Sprintf("0x%04x",id),"firmware_version":fmt.Sprintf("0x%04x",fw),"source_type":"ZY0602","identity_recognized":id==0x0602,"all_queries_completed":complete,"raw_words":words,"temperature_tenths_kelvin":words[3],"temperature_celsius":float64(int32(words[3])-2731)/10,"voltage_mV":words[4],"flags":fmt.Sprintf("0x%04x",words[5]),"discharge_flag":words[5]&1!=0,"full_flag":words[5]&512!=0,"remaining_capacity_mAh":words[6],"full_charge_capacity_mAh":words[7],"average_current_signed_mA":current,"OnePlus_API_current_mA":-current,"state_of_charge_percent":words[9],"data_range_plausible":plausible})
 }

 if code==0{
  if s["kernel_build"]!=uint32(26300)||s["processors"]!=uint32(8)||s["IRQL"]!=uint32(0)||s["firmware_match"]!=uint32(1)||s["firmware_bytes"]!=uint32(576)||s["firmware_status"]!=uint32(0)||s["map_calls"]!=maps||s["attempts"]!=uint32(1)||s["ready"]!=uint32(1)||s["fault"]!=uint32(0)||u(8)!=0||u(12)!=46||u(16)!=46||u(20)!=0xfffff||u(24)!=3||u(28)!=3||u(48)!=0||u(52)!=0||u(56)!=0||u(60)!=0||pc!=46||pd!=46||pf!=0||maps!=11||guard!=0||fifoEvents!=26||before["code"]!=uint32(0)||after["code"]!=uint32(0)||q(72)<q(64)||q(72)-q(64)>2000000{return nil,errors.New("success invariants")}
  if rxEvents!=20||nr!=1392+reads+10*(144+reads+writes){return nil,errors.New("independent native guards")}
 }
 return map[string]any{"status":s,"operation_code":code,"stage":u(8),"commands":u(12),"completed":u(16),"query_mask":u(20),"clean_mask":u(24),"restored_mask":u(28),"trace_events":n,"reads":reads,"writes":writes,"cancel_commands":u(48),"abort_commands":u(52),"uncertain_mask":u(56),"cancelled":u(60),"begin_us":q(64),"end_us":q(72),"native_reads":nr,"native_writes":nw,"map_calls":maps,"native_guard":guard,"policy_commands":pc,"policy_completed":pd,"policy_fault":pf,"before":before,"after":after,"gauges":rows,"gauge_configuration_commands":0},nil
}
