"""Infer axis order/sign from three checksum-valid, human-positioned captures.

Approximate point placement establishes orientation, not edge calibration.
"""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--suffix',default='01');p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();W=a.work;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
extents=[22680,24400];captures={};normalized={}
for label,folder in [('center','native-center-01'),('upper-left','native-upper-left-01'),('upper-right','native-upper-right-01')]:
 f=W/'private'/(folder[:-2]+a.suffix)/'decoded.json';j=json.loads(f.read_text());q=j['post_report'];assert q['Kind']==3 and q['HeaderValid']==q['BodyValid']==1 and q['Count']==1 and q['WithinProvisionalAxes']==1
 c=q['contacts'][0];captures[label]={'raw':[c['X'],c['Y']],'Id':c['Id'],'Type':c['Type'],'decoded_sha256':sha(f)};normalized[label]=[c['X']/extents[0],c['Y']/extents[1]]
left,right,center=(normalized[n]for n in ['upper-left','upper-right','center']);span=[right[i]-left[i]for i in range(2)];ha=max(range(2),key=lambda i:abs(span[i]));va=1-ha
assert abs(span[ha])>=.3 and abs(span[va])<.15,(span,ha)
vspan=center[va]-(left[va]+right[va])/2;assert abs(vspan)>.1,vspan
hpositive=span[ha]>0;vpositive=vspan>0
for label,r in normalized.items():
 u=r[ha]if hpositive else 1-r[ha];v=r[va]if vpositive else 1-r[va];assert 0<=u<=1 and 0<=v<=1
 captures[label]['display_normalized']=[u,v]
assert captures['upper-left']['display_normalized'][0]<.3 and captures['upper-left']['display_normalized'][1]<.3
assert captures['upper-right']['display_normalized'][0]>.7 and captures['upper-right']['display_normalized'][1]<.3
assert all(.35<=x<=.65 for x in captures['center']['display_normalized'])
out={'passed':True,'capture_count':3,'classification':'provisional axis order and signs from approximate human-positioned contacts','raw_extents_from_two_stock_DTB_candidates':extents,'display_horizontal_raw_axis':['X','Y'][ha],'display_horizontal_positive':hpositive,'display_vertical_raw_axis':['X','Y'][va],'display_vertical_positive':vpositive,'normalized_horizontal_formula':('raw_'+'XY'[ha]+'/'+str(extents[ha]))if hpositive else('1-raw_'+'XY'[ha]+'/'+str(extents[ha])),'normalized_vertical_formula':('raw_'+'XY'[va]+'/'+str(extents[va]))if vpositive else('1-raw_'+'XY'[va]+'/'+str(extents[va])),'captures':captures,'absolute_edge_calibration_qualified':False,'continuous_tracking_release_multitouch_qualified':False,'live_Windows_HID_input_qualified':False,'outer_screen_qualified':False,'limits':['Contact placement is supplied by the requested user test positions; it is approximate.','Native records prove one contact and header/body checksums, not absolute physical placement.','Stock coordinate extents are cross-checked by these samples but panel edges remain unmeasured.','This calculation does not issue phone commands or submit HID input.']}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
