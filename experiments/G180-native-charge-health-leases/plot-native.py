"""Plot retained physical measurements; no hardware access or fitted rates."""
from pathlib import Path
import json,struct
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
w=Path(__file__).resolve().parent;p=w/'private';r=json.loads((p/'native-analysis.json').read_text());assert r.get('passed')
s=json.loads((p/'sustained-intent.json').read_text());points=r['observations'];enable=r['wire']['enable_us'];off=r['wire']['final_off_us'];times=[]
for item in s['observations']:
 raw=(Path(item['directory'])/'G160.bin').read_bytes();stamp=struct.unpack_from('<Q',raw,56)[0];times.append((stamp/10-enable)/60000000)
fig,axes=plt.subplots(3,1,figsize=(10,8),sharex=True,layout='constrained');colors=['#0072B2','#D55E00']
for ax,field,label in zip(axes,['cells_mV','current_signed_mA','temperature_C'],['Voltage (mV per gauge)','Raw signed current (mA)','Temperature (°C)']):
 for i,color in enumerate(colors):ax.plot(times,[x[field][i]for x in points],color=color,marker='o',markersize=3,linewidth=1.5,label=f'Gauge {i+1}')
 ax.axvspan(0,(off-enable)/60000000,color='#009E73',alpha=.06)
 ax.axvline(0,color='#555555',linestyle=':',linewidth=1);ax.axvline((off-enable)/60000000,color='#555555',linestyle=':',linewidth=1)
 ax.set_ylabel(label);ax.grid(alpha=.2);ax.spines[['top','right']].set_visible(False)
axes[0].legend(loc='upper left',frameon=False,ncol=2);axes[1].set_ylim(-15,300);axes[2].set_ylim(20,40)
axes[-1].set_xlabel('Minutes from enable command (native interrupt clock)');axes[-1].set_xlim(min(times)-.1,max(times)+.2)
fig.suptitle('OnePlus Open · G180 native WinPE charging qualification',fontsize=15)
axes[0].set_title('300 mA FCC / 4470 mV profile · kernel off at 15-minute hard cap',fontsize=10,color='#444444')
fig.supxlabel('32 discrete paired captures; lines connect readings. Per-gauge rates and aggregate SOC are not calibrated.',fontsize=9,color='#444444')
out=Path('/path/to/user/Documents/GitHub/oneplusopen-win11/evidence/G180');fig.savefig(out/'native-charging.png',dpi=160);fig.savefig(out/'native-charging.svg');plt.close(fig)
svg=out/'native-charging.svg';svg.write_text('\n'.join(line.rstrip()for line in svg.read_text().splitlines())+'\n')
print(str(out/'native-charging.png'))
