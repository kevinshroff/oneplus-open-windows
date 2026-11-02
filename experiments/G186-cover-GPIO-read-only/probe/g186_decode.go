package main

import (
 "encoding/binary"
 "fmt"
)
var le=binary.LittleEndian
const captureBytes=616
const magic uint64=0x315243363831474f
var queries=[9][3]uint32{{0,0,8},{1,0,8},{2,0,8},{0,0x40,8},{1,0x40,8},{2,0x40,8},{0,0x10,1},{1,0x10,1},{2,0x10,1}}
var targets=[3]uint32{0x58f,0x78e,0x78f}
func encodeRequest(n uint64)[]byte{b:=make([]byte,32);le.PutUint32(b,32);le.PutUint32(b[4:],1);le.PutUint64(b[8:],magic);le.PutUint64(b[16:],n);return b}
func decodeStatus(b []byte)(map[string]any,error){
 if len(b)!=80||le.Uint32(b)!=80||le.Uint32(b[4:])!=1||le.Uint64(b[8:])!=magic{return nil,fmt.Errorf("status ABI")}
 s:=map[string]any{};for i,k:=range []string{"kernel_build","processors","IRQL","firmware_bytes","firmware_match","firmware_status","map_calls","attempts","ready","fault"}{s[k]=le.Uint32(b[16+4*i:])};for i,k:=range []string{"interrupt_time","frequency","sequence"}{s[k]=le.Uint64(b[56+8*i:])};return s,nil
}
func decodeCapture(b []byte,nonce uint64)(map[string]any,error){
 if len(b)!=captureBytes||le.Uint64(b[80:])!=nonce||le.Uint32(b[100:])!=0{return nil,fmt.Errorf("capture framing")};s,e:=decodeStatus(b[:80]);if e!=nil{return nil,e}
 r:=b[120:];u:=func(i int)uint32{return le.Uint32(r[i:])};size,code,count:=u(0),u(4),u(28)
 if size!=496&&!(size==0&&code>=1000)||count>9||u(16)>9||u(20)>9||le.Uint32(b[92:])!=u(20)||le.Uint64(b[112:])<le.Uint64(b[104:])||u(40)!=0||u(44)!=0{return nil,fmt.Errorf("capture fields")}
 rows:=[]map[string]any{};uncertain:=false
 for i:=uint32(0);i<count;i++{t:=r[136+40*i:];target,off,n,flags:=le.Uint32(t),le.Uint32(t[4:]),le.Uint32(t[8:]),le.Uint32(t[12:]);if target!=queries[i][0]||off!=queries[i][1]||n!=queries[i][2]||flags>63||flags&32!=0&&flags!=63||le.Uint32(t[36:])!=0{return nil,fmt.Errorf("fixed query %d",i)};row:=map[string]any{"ppid":fmt.Sprintf("0x%x",targets[target]),"offset":off,"bytes":n,"flags":flags,"completion":le.Uint32(t[24:])};if flags&32!=0{row["value_hex"]=fmt.Sprintf("%x",r[64+8*i:64+8*i+n])};if flags&8!=0&&flags&16==0{uncertain=true};rows=append(rows,row)}
 if code==0{if count!=9||u(16)!=9||u(20)!=9||u(36)!=1||le.Uint32(b[96:])!=0||le.Uint32(b[88:])!=u(12)+36{return nil,fmt.Errorf("incomplete success")};for i:=0;i<3;i++{v:=r[64+8*i:];if v[4]!=0x10||v[5]<0x10||v[5]>0x13{return nil,fmt.Errorf("GPIO identity")}}}
 return map[string]any{"status":s,"operation_code":code,"stage":u(8),"commands":u(20),"native_reads":le.Uint32(b[88:]),"native_observer_READ_commands":le.Uint32(b[92:]),"native_guard":le.Uint32(b[96:]),"post_routes_verified":u(36),"uncertain_read":uncertain,"traces":rows,"PMIC_configuration_writes":0,"panel_off_qualified":false},nil
}
