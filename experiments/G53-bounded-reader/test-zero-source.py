"""Replay the new native zero-contact packet through the unchanged stock functions."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--stock-model',type=Path,required=True);p.add_argument('--packet',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
old=a.stock_model.read_text();prefix=old.split('static unsigned Cases;',1)[0];packet=a.packet.read_bytes();assert len(packet)==26 and packet[:10]==bytes.fromhex('8003000000038600ffff')
main=r'''
int main(void){const uint8_t native[26]={__PACKET__};struct chip_data_brl c;struct point_info p[10],before[10];G53_FRAME f;memset(&c,0,sizeof(c));memset(p,0xa5,sizeof(p));memcpy(before,p,sizeof(p));c.ic_info.misc.touch_data_addr=G53_TOUCH_ADDRESS;c.pen_state=PEN_UP;c.touch_state=TOUCH_DOWN;memcpy(Wire,native,26);
 assert(checksum_cmp(native,8,CHECKSUM_MODE_U8_LE)==0&&checksum_cmp(native+8,2,CHECKSUM_MODE_U8_LE)==1);
 unsigned event=goodix_u32_trigger_reason(&c,0,0);assert((event&(1u<<IRQ_TOUCH))&&Reads==1&&Clears==1);
 assert(goodix_get_touch_points(&c,p,10)==0&&c.touch_state==TOUCH_UP&&!memcmp(p,before,sizeof(p)));
 G53DecodeReport(native,26,&f);assert(f.Kind==G53_FRAME_INVALID&&f.Error==G53_BAD_BODY&&f.HeaderValid&&!f.BodyValid&&!G53ReportClearable(native,26));
 puts("{\"passed\":true,\"unchanged_stock_functions\":3,\"stock_zero_count_releases_before_point_access\":true,\"stock_body_checksum_positive_failure_is_ignored\":true,\"G53_guard_stop_reproduced\":true}");return 0;}
'''.replace('__PACKET__',','.join(map(str,packet)))
f=a.output/'zero.c';f.write_text(prefix+main);exe=a.output/'zero';r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-parameter','-fsanitize=address,undefined','-I',str(W),str(f),str(W/'g53_report.c'),'-o',str(exe.resolve())],capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr);q=json.loads(r.stdout);q.update(ASan_UBSan=True,packet_sha256=hashlib.sha256(packet).hexdigest(),stock_model_sha256=hashlib.sha256(a.stock_model.read_bytes()).hexdigest(),G53_decoder_sha256=hashlib.sha256((W/'g53_report.c').read_bytes()).hexdigest(),native_actions=0,limits=['Stock Linux services, pen/grip/differ/motor support are modeled/disabled.','This proves stock zero-count interpretation and the existing G53 refusal; it does not make FFFF a valid checksum or qualify a corrected decoder.'])
(a.output/'tests.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps(q))
