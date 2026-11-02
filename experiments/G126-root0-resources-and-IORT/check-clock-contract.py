"""Execute pinned OEM clock-init control flow with modeled resources and faults."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
b = a.source.read_bytes()
assert hashlib.sha256(b).hexdigest() == '448c0862d10a692ce1131194bd25414d966dc570a9edb3757cf9c3d1aba99b11'
s = b.decode()
m = re.search(r'^static int msm_pcie_clk_init\(', s, re.M)
assert m
i = s.index('{', m.end()) + 1
depth = 1
while depth:
    depth += (s[i] == '{') - (s[i] == '}')
    i += 1
fn = s[m.start():i]

pre = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define PCIE_DBG(...) ((void)0)
#define PCIE_DBG2(...) ((void)0)
#define PCIE_ERR(...) ((void)0)
#define ICC_AVG_BW 1
#define ICC_PEAK_BW 2
#define MSM_PCIE_MAX_RESET 2
struct regulator{const char*name;int refs;};
struct clk{const char*name;int refs;};
struct reset_control{const char*name;};
struct msm_pcie_clk_info_t{struct clk*hdl;unsigned freq;const char*name;};
struct msm_pcie_reset_info_t{struct reset_control*hdl;const char*name;};
struct msm_pcie_dev_t{struct regulator*gdsc_core,*gdsc_phy;struct clk*pipe_clk_mux,*pipe_clk_ext_src,*ref_clk_src;void*icc_path;int num_clk;struct msm_pcie_clk_info_t clk[2];struct msm_pcie_reset_info_t reset[2];int rc_idx;void*pdev;};
static const char*Fail;static unsigned Failures;
static int Test(const char*op,const char*name){char text[64];snprintf(text,sizeof(text),"%s:%s",op,name);if(!strcmp(Fail,text)){Failures++;return -19;}return 0;}
static int regulator_enable(struct regulator*p){int r=Test("enable",p->name);if(!r)p->refs++;return r;}
static int regulator_disable(struct regulator*p){assert(p->refs>0);p->refs--;return 0;}
static int clk_set_parent(struct clk*p,struct clk*q){assert(p&&q);return Test("parent",p->name);}
static int icc_set_bw(void*p,unsigned a,unsigned b){assert(p&&a==1&&b==2);return Test("vote","icc");}
static int clk_set_rate(struct clk*p,unsigned r){assert(r);return Test("rate",p->name);}
static int clk_prepare_enable(struct clk*p){int r=Test("enable",p->name);if(!r)p->refs++;return r;}
static void clk_disable_unprepare(struct clk*p){if(p->refs)p->refs--;}
static int reset_control_assert(struct reset_control*p){return Test("assert",p->name);}
static int reset_control_deassert(struct reset_control*p){return Test("deassert",p->name);}
static void usleep_range(unsigned a,unsigned b){assert(a==1000&&b==1005);}
'''
main = r'''
int main(void){const char*cases[]={"none","enable:phy","vote:icc","enable:clock0","enable:clock1","rate:clock0","parent:mux","assert:reset0","deassert:reset0","deassert:reset1"};
 puts("{\"passed\":true,\"actual_source_function\":true,\"resources_and_faults_modeled\":true,\"native_operations\":0,\"cases\":[");
 for(unsigned at=0;at<sizeof(cases)/sizeof(cases[0]);at++){
  struct regulator core={"core",0},phy={"phy",0};struct clk c0={"clock0",0},c1={"clock1",0},mux={"mux",0},ext={"external",0},xo={"xo",0};struct reset_control r0={"reset0"},r1={"reset1"};
  struct msm_pcie_dev_t d={.gdsc_core=&core,.gdsc_phy=&phy,.pipe_clk_mux=&mux,.pipe_clk_ext_src=&ext,.ref_clk_src=&xo,.icc_path=(void*)1,.num_clk=2,.clk={{&c0,1,"clock0"},{&c1,1,"clock1"}},.reset={{&r0,"reset0"},{&r1,"reset1"}}};
  Fail=cases[at];Failures=0;int rc=msm_pcie_clk_init(&d);
  if(at==0)assert(!rc&&core.refs==1&&phy.refs==1&&c0.refs==1&&c1.refs==1&&!Failures);
  else assert(Failures);
  if(at==1)assert(rc<0&&core.refs==1&&!phy.refs);
  if(at==2)assert(rc<0&&core.refs==1&&phy.refs==1);
  if(at==3)assert(!rc&&!c0.refs&&c1.refs==1&&core.refs==1&&phy.refs==1);
  if(at==4||at==5)assert(!rc&&!core.refs&&!phy.refs&&!c0.refs&&!c1.refs);
  if(at>=6&&at<=8)assert(!rc&&core.refs==1&&phy.refs==1&&c0.refs==1&&c1.refs==1);
  if(at==9)assert(rc<0&&core.refs==1&&phy.refs==1&&c0.refs==1&&c1.refs==1);
  printf("{\"fault\":\"%s\",\"return\":%d,\"injected_errors_observed\":%u,\"core_refs\":%d,\"phy_refs\":%d,\"clock_refs\":[%d,%d]}%s\n",cases[at],rc,Failures,core.refs,phy.refs,c0.refs,c1.refs,at+1==sizeof(cases)/sizeof(cases[0])?"":",");
 }
 puts("]}");return 0;
}
'''
model = a.output / 'model.c'
model.write_text(pre + fn + main)
exe = a.output / 'test'
r = subprocess.run(['clang', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(model), '-o', str(exe)], capture_output=True, text=True)
assert r.returncode == 0, r.stderr
r = subprocess.run([str(exe.resolve())], capture_output=True, text=True)
assert r.returncode == 0 and not r.stderr, (r.stdout, r.stderr)
result = json.loads(r.stdout)
result['source_sha256'] = hashlib.sha256(b).hexdigest()
result['extracted_function_sha256'] = hashlib.sha256(fn.encode()).hexdigest()
result['limit'] = 'Two modeled clocks and resets expose source return/unwind boundaries; no actual power/clock/PHY or Android execution.'
(a.output / 'tests.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
