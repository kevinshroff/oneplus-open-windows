"""Re-audit exported raw capture, frozen session and original stack cleanup."""
from pathlib import Path
import argparse,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(W/'audit-native.py'),'--evidence',str(a.evidence.resolve()),'--run','idle','--output',str(a.output.resolve())],check=True)
