package main
import("encoding/binary";"errors")
var le=binary.LittleEndian
const captureBytes=279880
var bases=[1]uint32{0x880000}
func kind(n uint32)uint32{if n&1==0{return 1};return 2}
func payload(n uint32)uint32{return []uint32{0x36,0x07,0x36}[(n%6)/2]}
var offsets=[]uint32{0,4,0x24,0x28,0x40,0x48,0x4c,0x64,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0x800,0x804,0xe24,0xe28,0x258,0x7c,0x254,0x260,0x264,0x284,0x288,0x600,0x604,0x614,0x630,0x634,0x644,0x80c,0x810,0x814,0x908}
func allowed(at uint32)bool{
 for i,base:=range bases{for j,o:=range offsets{if i==1&&j==17{o=0x50};if i==1&&j==18{continue};if at==base+o{return true}};if at==base+0x780{return true}}
 return false
}
func decodeStatus(b []byte)(map[string]any,error){
 if len(b)!=80||le.Uint32(b)!=80||le.Uint32(b[4:])!=1||string(b[8:16])!="OG113SC1"{return nil,errors.New("G113 status ABI")}
 v:=map[string]any{};for i,n:=range []string{"kernel_build","processors","IRQL","firmware_bytes","firmware_match","firmware_status","map_calls","attempts","ready","fault"}{v[n]=le.Uint32(b[16+4*i:])};for i,n:=range []string{"interrupt_time","frequency","sequence"}{v[n]=le.Uint64(b[56+8*i:])};return v,nil
}
func probe(b []byte,optional bool)(map[string]any,error){
 if len(b)!=8728{return nil,errors.New("probe size")};if optional&&le.Uint32(b)==0{for _,v:=range b{if v!=0{return nil,errors.New("partial missing probe")}};return map[string]any{"not_run":true},nil};if le.Uint32(b)!=8728{return nil,errors.New("probe size")};u:=func(o int)uint32{return le.Uint32(b[o:])}
 if u(4)>6||u(12)>1024||u(16)>u(12)||u(20)>3||u(24)>3||u(28)>15{return nil,errors.New("probe bounds")}
 if u(4)==0&&(u(12)!=357||u(16)!=357||u(20)!=1||u(24)!=1||u(28)!=3){return nil,errors.New("probe complete bounds")}
 return map[string]any{"code":u(4),"reads":u(12),"ready_mask":u(20),"clock_words_unchanged_mask":u(24),"pin_words_unchanged_mask":u(28)},nil
}
func decodeCapture(b []byte,nonce uint64)(map[string]any,error){
 if len(b)!=captureBytes{return nil,errors.New("capture size")};s,e:=decodeStatus(b[:80]);if e!=nil{return nil,e};if le.Uint64(b[80:])!=nonce{return nil,errors.New("nonce")}
 r:=b[120:];u:=func(o int)uint32{return le.Uint32(r[o:])};q:=func(o int)uint64{return le.Uint64(r[o:])}
 nr,nw,maps,guard,pc,pd,pf:=le.Uint32(b[88:]),le.Uint32(b[92:]),le.Uint32(b[96:]),le.Uint32(b[100:]),le.Uint32(b[104:]),le.Uint32(b[108:]),le.Uint32(b[112:])
 code,n,reads,writes:=u(4),u(32),u(40),u(44)
 if u(0)!=279760||(code>12&&code!=1004&&code!=1005)||u(12)>6||u(16)>u(12)||u(20)>7||u(24)>1||u(28)>1||n>16384||u(36)!=0||reads>16384||writes>512||u(48)>6||u(52)>6||u(56)>1||u(60)>1||nr>200000||nw>512||maps>7||guard>4||pc>6||pd>pc||pf>1||le.Uint32(b[116:])!=0{return nil,errors.New("capture bounds")}
 readEvents,writeEvents,cmdEvents,fifoEvents,rxEvents:=uint32(0),uint32(0),uint32(0),uint32(0),uint32(0)
 for i:=uint32(0);i<n;i++{
  at:=17616+int(i)*16;k,a,v,cmd:=le.Uint32(r[at:]),le.Uint32(r[at+4:]),le.Uint32(r[at+8:]),le.Uint32(r[at+12:]);if cmd>6{return nil,errors.New("trace command")}
  if k==1{if !allowed(a){return nil,errors.New("read trace address")};if a&4095==0x780{if rxEvents>=3||a!=bases[0]+0x780||(code==0&&v&255!=u(80+int(rxEvents)*4)){return nil,errors.New("raw word/trace disagreement")};rxEvents++};readEvents++}else if k==2{
   base:=uint32(0);for _,x:=range bases{if a>=x&&a-x<4096{base=x}};if base==0{return nil,errors.New("write trace base")}
   switch a-base{
   case 0x26c:if v!=1{return nil,errors.New("TX length")}
   case 0x270:if v!=1&&v!=2{return nil,errors.New("RX length")}
   case 0x80c:if v>1{return nil,errors.New("watermark")}
   case 0x600:if cmdEvents>=6||a!=bases[0]+0x600||v!=[]uint32{0x0800de04,0x0800de04,0x1000de00}[kind(cmdEvents)]{return nil,errors.New("fixed command")};cmdEvents++
   case 0x700:if cmdEvents==0||v!=payload(cmdEvents-1){return nil,errors.New("fixed register selection")};fifoEvents++
   case 0x604:if v!=4&&v!=2{return nil,errors.New("cancel/abort")}
   case 0x618:if v==0||v&^uint32(0x7fc07e7f)!=0{return nil,errors.New("owned IRQ clear")}
   default:return nil,errors.New("write trace offset")
   };writeEvents++
  }else{return nil,errors.New("trace kind")}
 }
 if readEvents>reads||writeEvents>writes||cmdEvents>u(12)||nw!=writeEvents||(code==0&&(reads!=readEvents||writes!=writeEvents||u(12)!=cmdEvents)){return nil,errors.New("trace counters")}
 before,e:=probe(r[160:8888],code==1004||code==1005);if e!=nil{return nil,e};after,e:=probe(r[8888:17616],code==1004||code==1005||u(56)!=0);if e!=nil{return nil,e}
 raw:=[]uint32{u(80),u(84),u(88)};for j:=0;j<20;j++{v:=u(80+4*j);if v>255||(j>=3&&v!=0){return nil,errors.New("unused/byte query slot")}}
 row:=map[string]any{"controller":"0x880000","address":"0x6f","raw_bytes":raw,"all_queries_completed":u(20)==7,"identity_recognized":raw[0]==0x67&&raw[2]==0x67,"telemetry_usable":false}
 if code==0{if raw[0]!=0x67||raw[2]!=0x67{return nil,errors.New("identity changed")};row["source_type"]="SC8547A";row["telemetry_usable"]=true;row["charge_enable_bit7"]=(raw[1]&128)!=0}

 if code==0{
  if s["kernel_build"]!=uint32(26300)||s["processors"]!=uint32(8)||s["IRQL"]!=uint32(0)||s["firmware_match"]!=uint32(1)||s["firmware_bytes"]!=uint32(576)||s["firmware_status"]!=uint32(0)||s["map_calls"]!=maps||s["attempts"]!=uint32(1)||s["ready"]!=uint32(1)||s["fault"]!=uint32(0)||u(8)!=0||u(12)!=6||u(16)!=6||u(20)!=7||u(24)!=1||u(28)!=1||u(48)!=0||u(52)!=0||u(56)!=0||u(60)!=0||pc!=6||pd!=6||pf!=0||maps!=7||guard!=0||fifoEvents!=3||before["code"]!=uint32(0)||after["code"]!=uint32(0)||q(72)<q(64)||q(72)-q(64)>2000000{return nil,errors.New("success invariants")}
  if rxEvents!=3||nr!=714+reads+10*(74+reads+writes){return nil,errors.New("independent native guards")}
 }
 return map[string]any{"status":s,"operation_code":code,"stage":u(8),"commands":u(12),"completed":u(16),"query_mask":u(20),"clean_mask":u(24),"restored_mask":u(28),"trace_events":n,"reads":reads,"writes":writes,"cancel_commands":u(48),"abort_commands":u(52),"uncertain_mask":u(56),"cancelled":u(60),"begin_us":q(64),"end_us":q(72),"native_reads":nr,"native_writes":nw,"map_calls":maps,"native_guard":guard,"policy_commands":pc,"policy_completed":pd,"policy_fault":pf,"before":before,"after":after,"external_charger":row,"peripheral_configuration_writes":0},nil
}
