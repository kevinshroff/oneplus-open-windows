"""Compare G54 wire decoding with unchanged pinned stock Goodix functions."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
c=a.inputs/'reference-goodix/GT9966-goodix_brl_core.c';h=a.inputs/'reference-goodix/GT9966-goodix_brl_core.h';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(c)=='f0e09004861d89392f163709a64a4effe2da0b7831a2d20f57b41fcbff63674a' and sha(h)=='4605c36d099607bfdf912085171b1c8c049ab01cf8762c6446bfee13b9c5eab3'
s=c.read_text();head=h.read_text()
def extract(name):
 m=re.search(r'^(?:static )?(?:int|u32) '+name+r'\([^;]*?\)\s*\{',s,re.M);assert m,name;i=m.end();depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
names=['checksum_cmp','goodix_u32_trigger_reason','goodix_get_touch_points'];bodies={n:extract(n)for n in names}
constants={'MAX_POINT_NUM':10,'MAX_GT_IRQ_DATA_LENGTH':90,'GOODIX_TOUCH_EVENT':128,'GOODIX_REQUEST_EVENT':64,'GOODIX_GESTURE_EVENT':32,'GOODIX_FINGER_PRINT_EVENT':8,'GOODIX_FINGER_STATUS_EVENT':2,'GOODIX_FINGER_IDLE_EVENT':4,'GRIP_COOR_SUPPORT_FLAG':1,'EDGE_INPUT_COORD':0x102f6,'EDGE_INPUT_OFFSET':4,'IRQ_EVENT_HEAD_LEN':8,'BYTES_PER_POINT':8,'COOR_DATA_CHECKSUM_SIZE':2,'POINT_NUM_OFFSET':2,'IRQ_EVENT_TYPE_OFFSET':0,'POINT_TYPE_STYLUS':3,'POINT_TYPE_STYLUS_HOVER':1,'FINGER_CHECK':15,'TOUCH_POINT_OFFECT':6,'TOUCH_CHECKSUM_OFFECT':1,'TOUCH_ALL_OFFECT':10,'BYTES_PER_EDGE':4}
for n,v in constants.items():
 m=re.search(r'^#define\s+'+n+r'\s+(0[xX][0-9a-fA-F]+|[0-9]+)',head,re.M);assert m and int(m[1],0)==v,n
prefix=r'''
#include "g54_report.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t u32;typedef int32_t s32;
#define TPD_DEBUG(...) ((void)0)
#define TPD_INFO(...) ((void)0)
#define unlikely(x) (x)
#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define SET_BIT(v,b) ((v)|=1u<<(b))
#define DATA_CHANGE(x) (x)
#define MAX_GT_EDGE_DATA_LENGTH 42
#define TOUCH_UP 0
#define TOUCH_DOWN 1
#define ALL_TOUCH_UP 0
#define TX_LEFT_RIGHT 0
#define TX_DOWN_UP 1
#define IRQ_IGNORE 0
#define PEN_UP 0
#define PEN_DOWN 1
enum{IRQ_GESTURE=0,IRQ_PEN_REPORT=1,IRQ_FW_HEALTH=2,IRQ_PEN=3,IRQ_TOUCH=4,IRQ_FINGERPRINT=5,CHECKSUM_MODE_U8_LE=0,CHECKSUM_MODE_U16_LE=1};
struct point_info{int x,y,touch_major,width_major,tx_press,rx_press,tx_er,rx_er,status;};
struct goodix_ic_info_misc{u32 touch_data_addr;};
struct chip_data_brl{u8 touch_data[90],edge_data[42];struct{struct goodix_ic_info_misc misc;}ic_info;
 bool kernel_grip_support,enable_differ_mode,abnormal_grip_coor,get_grip_coor,pen_enable,pen_support,check_palm_flag,motor_coord_support,fp_down_flag;
 int touch_state,pen_state,hardware_trx_direction,max_y,diff_size;int16_t*diff_buf;struct{int tx_num,rx_num;}*hw_res;};
static uint8_t Wire[90];static uint32_t ReadAddresses[3],ReadLengths[3];static unsigned Reads,Clears;
static unsigned le16_to_cpup(const __le16*p){const uint8_t*b=(const uint8_t*)p;return(unsigned)b[0]|((unsigned)b[1]<<8);}
static int goodix_reg_read(struct chip_data_brl*c,u32 at,u8*out,int n){(void)c;assert(Reads<3&&at>=G54_TOUCH_ADDRESS&&at-G54_TOUCH_ADDRESS+(unsigned)n<=90);ReadAddresses[Reads]=at;ReadLengths[Reads++]=(unsigned)n;memcpy(out,Wire+(at-G54_TOUCH_ADDRESS),(unsigned)n);return 0;}
static int goodix_clear_irq(struct chip_data_brl*c){(void)c;Clears++;return 0;}
static void goodix_read_differ(struct chip_data_brl*c){(void)c;assert(0);}
static void goodix_print_differ(int16_t*a,int b,int c,int d){(void)a;(void)b;(void)c;(void)d;assert(0);}
static int goodix_check_finger(struct chip_data_brl*c,struct point_info*p,int a,int b,int d){(void)c;(void)p;(void)a;(void)b;(void)d;assert(0);return 0;}
static void check_dynamic_limit(struct chip_data_brl*c,struct point_info*p,int id){(void)c;(void)p;(void)id;assert(0);}
'''
main=r'''
static unsigned Cases;
static unsigned Le(const uint8_t*p){return(unsigned)p[0]|((unsigned)p[1]<<8);}
static void Seal(uint8_t*b,unsigned n){unsigned i,sum=0;assert(n>=2);for(i=0;i<n-2;i++)sum+=b[i];b[n-2]=(uint8_t)sum;b[n-1]=(uint8_t)(sum>>8);}
static void Make(unsigned count,unsigned seed){unsigned k;memset(Wire,0,sizeof(Wire));Wire[0]=0x80;Wire[1]=(uint8_t)seed;Wire[2]=(uint8_t)((seed&15)<<4|count);Wire[3]=23;Wire[4]=11;Wire[5]=3;
 for(k=0;k<count;k++){uint8_t*p=Wire+8+k*8;unsigned x=(seed*7411+k*613)&65535,y=(seed*1123+k*177)&65535;p[0]=(uint8_t)(((k+seed)%10)<<4);p[1]=(uint8_t)(seed^0x55);p[2]=(uint8_t)x;p[3]=(uint8_t)(x>>8);p[4]=(uint8_t)y;p[5]=(uint8_t)(y>>8);p[6]=(uint8_t)(k+seed);p[7]=(uint8_t)(seed*11+k);}
 Seal(Wire+8,count*8+2);Seal(Wire,8);}
static unsigned Stock(struct point_info*p){struct chip_data_brl c;unsigned events;memset(&c,0,sizeof(c));c.ic_info.misc.touch_data_addr=G54_TOUCH_ADDRESS;Reads=Clears=0;events=goodix_u32_trigger_reason(&c,0,0);if(events&(1u<<IRQ_TOUCH))goodix_get_touch_points(&c,p,10);return events;}
int main(void){unsigned count,seed,i,bit,full,expectedMask,bounds;G54_FRAME f;struct point_info points[10];uint8_t saved[90];
 for(count=0;count<=10;count++)for(seed=0;seed<256;seed++){
  Make(count,seed);full=count*8+10;G54DecodeReport(Wire,26,&f);
  if(count>2){assert(f.Kind==G54_FRAME_MORE&&f.TailBytes==(count-2)*8&&f.MeaningfulBytes==full&&!G54ReportClearable(Wire,26));Cases++;G54DecodeReport(Wire,full,&f);}
  assert(f.Kind==G54_FRAME_CONTACTS&&f.HeaderValid&&(count?f.BodyValid:(!f.BodyChecked&&!f.BodyValid&&f.MeaningfulBytes==8))&&f.Count==count&&G54ReportClearable(Wire,count>2?full:26));
  memset(points,0,sizeof(points));assert(Stock(points)&(1u<<IRQ_TOUCH));assert(Clears==1&&Reads==(count>2?2u:1u)&&ReadAddresses[0]==G54_TOUCH_ADDRESS&&ReadLengths[0]==26);
  if(count>2)assert(ReadAddresses[1]==G54_TAIL_ADDRESS&&ReadLengths[1]==(count-2)*8);
  expectedMask=0;bounds=1;for(i=0;i<count;i++){G54_CONTACT*c=&f.Contacts[i];unsigned id=c->Id;assert(id<10&&points[id].status==1&&(unsigned)points[id].x==c->X&&(unsigned)points[id].y==c->Y&&(unsigned)points[id].touch_major==c->Major&&(unsigned)points[id].width_major==c->Minor);expectedMask|=1u<<id;if(c->X>22680||c->Y>24400)bounds=0;}
  assert(f.ContactMask==expectedMask&&f.WithinProvisionalAxes==bounds);Cases++;
 }
 /* The stock getter treats zero count as UP before point access. Every
  * possible trailing word must remain unparsed, including the native FFFF. */
 for(unsigned word=0;word<65536;word++){
  Make(0,0);for(i=8;i<90;i++)Wire[i]=(uint8_t)(word+i*37);Wire[8]=(uint8_t)word;Wire[9]=(uint8_t)(word>>8);
  memset(points,0xa5,sizeof(points));struct point_info untouched[10];memcpy(untouched,points,sizeof(points));
  assert(Stock(points)&(1u<<IRQ_TOUCH));assert(!memcmp(points,untouched,sizeof(points))&&Reads==1&&Clears==1);
  G54DecodeReport(Wire,26,&f);assert(f.Kind==G54_FRAME_CONTACTS&&f.Count==0&&f.HeaderValid&&f.HeaderChecked&&!f.BodyChecked&&!f.BodyValid&&f.MeaningfulBytes==8&&!f.ContactMask&&f.PointType==0&&G54ReportClearable(Wire,26));
  G54DecodeReport(Wire,8,&f);assert(f.Kind==G54_FRAME_CONTACTS&&f.MeaningfulBytes==8&&!f.BodyChecked);Cases++;
 }
 Make(0,0);memcpy(saved,Wire,90);for(i=0;i<8;i++)for(bit=0;bit<8;bit++){memcpy(Wire,saved,90);Wire[i]^=(uint8_t)(1u<<bit);assert(!G54ReportClearable(Wire,26));Cases++;}
 Make(10,31);memcpy(saved,Wire,90);
 for(i=8;i<90;i++)for(bit=0;bit<8;bit++){memcpy(Wire,saved,90);Wire[i]^=(uint8_t)(1u<<bit);G54DecodeReport(Wire,90,&f);assert(f.Kind!=G54_FRAME_CONTACTS&&!G54ReportClearable(Wire,90));Cases++;}
 for(i=0;i<8;i++)for(bit=0;bit<8;bit++){memcpy(Wire,saved,90);Wire[i]^=(uint8_t)(1u<<bit);G54DecodeReport(Wire,90,&f);assert(!G54ReportClearable(Wire,90));if(i==0&&bit==7)assert(f.Kind==G54_FRAME_IDLE&&!f.HeaderChecked);Cases++;}
 Make(2,0);Wire[24]^=1;assert(checksum_cmp(Wire+8,18,CHECKSUM_MODE_U8_LE)==1);memset(points,0,sizeof(points));assert(Stock(points)&(1u<<IRQ_TOUCH));G54DecodeReport(Wire,26,&f);assert(f.Kind==G54_FRAME_INVALID&&f.Error==G54_BAD_BODY&&!G54ReportClearable(Wire,26));Cases++;
 for(count=11;count<=15;count++){Make(0,0);Wire[2]=(uint8_t)count;Seal(Wire,8);G54DecodeReport(Wire,26,&f);assert(f.Error==G54_BAD_COUNT&&!G54ReportClearable(Wire,26));Cases++;}
 for(i=10;i<16;i++){Make(1,0);Wire[8]=(uint8_t)(i<<4);Seal(Wire+8,10);G54DecodeReport(Wire,26,&f);assert(f.Error==G54_BAD_ID&&!f.ContactMask&&!G54ReportClearable(Wire,26));Cases++;}
 Make(2,0);Wire[16]=Wire[8];Seal(Wire+8,18);G54DecodeReport(Wire,26,&f);assert(f.Error==G54_DUPLICATE_ID&&!f.ContactMask&&!G54ReportClearable(Wire,26));Cases++;
 for(i=1;i<=3;i+=2){Make(1,0);Wire[8]|=(uint8_t)i;Seal(Wire+8,10);G54DecodeReport(Wire,26,&f);assert(f.Kind==G54_FRAME_UNSUPPORTED&&f.Error==G54_UNSUPPORTED_PEN&&!G54ReportClearable(Wire,26));Cases++;}
 for(i=0;i<256;i++){memset(Wire,0,90);Wire[0]=0x40;Wire[2]=(uint8_t)i;Seal(Wire,8);G54DecodeReport(Wire,26,&f);assert((f.Kind==G54_FRAME_REQUEST_ZERO)==(i==0));assert(G54ReportClearable(Wire,26)==(i==0));Cases++;}
 for(i=0;i<256;i++){Make(1,0);Wire[0]=(uint8_t)i;Seal(Wire,8);G54DecodeReport(Wire,26,&f);assert(G54ReportClearable(Wire,26)==((i&0x80u)&&!(i&~0x8bu)));Cases++;}
 Make(10,0);for(i=0;i<90;i++){G54DecodeReport(Wire,i,&f);assert(!G54ReportClearable(Wire,i));Cases++;}
 G54DecodeReport(NULL,90,&f);assert(f.Error==G54_BAD_LENGTH);G54DecodeReport(Wire,91,&f);assert(f.Error==G54_BAD_LENGTH);Cases+=2;
 memset(Wire,0xff,90);Wire[0]=0;G54DecodeReport(Wire,26,&f);assert(f.Kind==G54_FRAME_IDLE&&!f.HeaderChecked&&!G54ReportClearable(Wire,26));Cases++;
 assert(Le(saved+88)==(unsigned)(saved[88]|saved[89]<<8));
 printf("{\"passed\":true,\"cases\":%u,\"unchanged_stock_trigger_and_coordinate_functions\":true,\"valid_contact_layout_and_prefetch_tail_match\":true,\"positive_checksum_failure_bug_reproduced_and_refused\":true,\"duplicate_and_invalid_contact_IDs_refused\":true}\n",Cases);return 0;}
'''
f=a.output/'source-model.c';f.write_text(prefix+'\n'.join('#define '+n+' '+str(v)for n,v in constants.items())+'\n'+'\n'.join(bodies.values())+'\n'+main);exe=a.output/'source-model';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined','-I',str(W),str(W/'g54_report.c'),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr);r=json.loads(q.stdout);r.update(header_only_zero_count_semantics=True,all65536_zero_trailing_words_unparsed=True,ASan_UBSan=True,stock_C_sha256=sha(c),stock_H_sha256=sha(h),unchanged_function_sha256={n:hashlib.sha256(b.encode()).hexdigest()for n,b in bodies.items()},source_sha256={n:sha(W/n)for n in ['g54_report.c','g54_report.h']},native_commands_submitted=0,limits=['Stock Linux I/O, optional grip/pen/palm/motor/differ dependencies and framework point structures are explicit host models.','Only non-stylus raw contact layout is covered; live hardware, contact/rotation calibration and Windows input delivery are unqualified.','Driver read/clear behavior is modeled; no native event write occurs.']);(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
