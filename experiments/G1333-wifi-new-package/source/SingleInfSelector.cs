using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
public sealed class Matched4478Selector : IDisposable {
 [StructLayout(LayoutKind.Sequential)] public struct DEV {public uint cbSize; public Guid ClassGuid; public uint DevInst; public UIntPtr Reserved;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct PARAMS {public uint cbSize,Flags,FlagsEx; public IntPtr hwndParent,InstallMsgHandler,InstallMsgHandlerContext,FileQueue; public UIntPtr ClassInstallReserved; public uint Reserved; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string DriverPath;}
 [StructLayout(LayoutKind.Sequential)] public struct FT {public uint Low,High;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct DRIVER {public uint cbSize,DriverType; public UIntPtr Reserved; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Description; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Mfg; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Provider; public FT DriverDate; public ulong DriverVersion;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct DETAIL {public uint cbSize;public FT InfDate;public uint CompatIDsOffset,CompatIDsLength;public UIntPtr Reserved;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Section;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string InfFile;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Description;public ushort HardwareFirst;}
 const string SETUP="C:\\Windows\\System32\\setupapi.dll";
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupCopyOEMInfW(string source,string media,uint mediaType,uint copyStyle,StringBuilder destination,uint chars,out uint required,out IntPtr component);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupGetInfDriverStoreLocationW(string file,IntPtr platform,string locale,StringBuilder destination,uint chars,out uint required);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr SetupDiGetClassDevsW(ref Guid g,IntPtr e,IntPtr w,uint flags);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiOpenDeviceInfoW(IntPtr h,string id,IntPtr p,uint flags,ref DEV d);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiGetDeviceInstallParamsW(IntPtr h,ref DEV d,ref PARAMS p);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiSetDeviceInstallParamsW(IntPtr h,ref DEV d,ref PARAMS p);
 [DllImport(SETUP,SetLastError=true)]static extern bool SetupDiBuildDriverInfoList(IntPtr h,ref DEV d,uint type);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiEnumDriverInfoW(IntPtr h,ref DEV d,uint type,uint i,ref DRIVER p);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiGetDriverInfoDetailW(IntPtr h,ref DEV d,ref DRIVER p,IntPtr detail,uint bytes,out uint need);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiSetSelectedDriverW(IntPtr h,ref DEV d,ref DRIVER p);
 [DllImport(SETUP)]static extern bool SetupDiDestroyDriverInfoList(IntPtr h,ref DEV d,uint type);
 [DllImport(SETUP)]static extern bool SetupDiDestroyDeviceInfoList(IntPtr h);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr SetupOpenInfFileW(string f,IntPtr c,uint style,out uint errorLine);
 [DllImport(SETUP)]static extern void SetupCloseInfFile(IntPtr h);
 [DllImport(SETUP,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiGetActualSectionToInstallExW(IntPtr h,string section,IntPtr platform,StringBuilder actual,uint chars,out uint need,IntPtr extension,IntPtr reserved);

 [DllImport("C:\\Windows\\System32\\cfgmgr32.dll")]static extern uint CM_Get_DevNode_Status(out uint status,out uint problem,uint inst,uint flags);
 [DllImport("C:\\Windows\\System32\\newdev.dll",SetLastError=true)]static extern bool DiInstallDevice(IntPtr parent,IntPtr h,ref DEV d,ref DRIVER driver,uint flags,out bool needReboot);
 IntPtr h=new IntPtr(-1); DEV d; DRIVER driver; bool list,attempted; public PARAMS Parameters; public DETAIL SelectedDetail; public uint Status,Problem; public uint DriverCount; public string CandidateError,InfSha256,ResolvedSection; public ulong Version {get{return driver.DriverVersion;}} public string Description {get{return driver.Description;}} public string Provider {get{return driver.Provider;}}
 static void Check(bool ok,string step){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),step);}
 static string Hash(string f){using(var s=SHA256.Create())using(var x=File.OpenRead(f)){return BitConverter.ToString(s.ComputeHash(x)).Replace("-","").ToLowerInvariant();}}
 static bool stageAttempted;
 public static object StagePackageOnce(string exactSourceInf){
  if(stageAttempted)throw new Exception("No repeated package import");
  exactSourceInf=Path.GetFullPath(exactSourceInf);if(exactSourceInf.Length>=260||Hash(exactSourceInf)!="3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb")throw new Exception("Exact matched source INF required");
  stageAttempted=true;uint required;IntPtr component;StringBuilder published=new StringBuilder(260);
  Check(SetupCopyOEMInfW(exactSourceInf,Path.GetDirectoryName(exactSourceInf),1,0,published,260,out required,out component),"One package DriverStore import, no device install");
  if(required<1||required>260)throw new Exception("Bounded actual published INF path");string oem=Path.GetFullPath(published.ToString());
  if(!oem.StartsWith(@"C:\Windows\INF\",StringComparison.OrdinalIgnoreCase)||Hash(oem)!="3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb")throw new Exception("Actual published new INF hash/path differs");
  StringBuilder store=new StringBuilder(260);Check(SetupGetInfDriverStoreLocationW(oem,IntPtr.Zero,null,store,260,out required),"Resolve actual preinstalled DriverStore INF");
  if(required<1||required>260)throw new Exception("Bounded actual DriverStore path");string inf=Path.GetFullPath(store.ToString());
  if(!inf.StartsWith(@"C:\Windows\System32\DriverStore\FileRepository\",StringComparison.OrdinalIgnoreCase)||Hash(inf)!="3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb")throw new Exception("Actual DriverStore new INF hash/path differs");
  return new {publishedInf=oem,driverStoreInf=inf,InfSHA256=Hash(inf),packageImportCalls=1,driverInstallCalls=0,automaticReboot=false};
 }
 public static uint SelectionFlags(uint flags){return (flags & ~(0x01000000U|0x00080000U))|0x00810000U;}
 public static uint SelectionFlagsEx(uint flagsEx){return (flagsEx & ~0x04000000U)|0x00000800U;}
 public static object LayoutOnly(){return new {pointer_bytes=IntPtr.Size,DEV_bytes=Marshal.SizeOf(typeof(DEV)),PARAMS_bytes=Marshal.SizeOf(typeof(PARAMS)),DRIVER_bytes=Marshal.SizeOf(typeof(DRIVER)),DETAIL_bytes=Marshal.SizeOf(typeof(DETAIL)),native_calls=0};}
 public void CurrentInstallProblem(){uint rc=CM_Get_DevNode_Status(out Status,out Problem,d.DevInst,0);if(rc!=0||(Problem!=32&&Problem!=56))throw new Exception("Current devnode Code32 or Code56 required; CR="+rc+" problem="+Problem);}
 public Matched4478Selector(string id,string exactInf){
  if(IntPtr.Size!=8||Marshal.SizeOf(typeof(DEV))!=32||Marshal.SizeOf(typeof(PARAMS))!=584||Marshal.SizeOf(typeof(DRIVER))!=1568||Marshal.SizeOf(typeof(DETAIL))!=1584)throw new Exception("Exact native64 SetupAPI layouts required");
  Guid net=new Guid("4d36e972-e325-11ce-bfc1-08002be10318");h=SetupDiGetClassDevsW(ref net,IntPtr.Zero,IntPtr.Zero,2);Check(h!=new IntPtr(-1),"Present NET set");
  try {
   d.cbSize=32;Check(SetupDiOpenDeviceInfoW(h,id,IntPtr.Zero,0,ref d),"Exact present instance");if(d.ClassGuid!=net)throw new Exception("NET class required");CurrentInstallProblem();
   Parameters=new PARAMS();Parameters.cbSize=584;Check(SetupDiGetDeviceInstallParamsW(h,ref d,ref Parameters),"Read local install params");
   // Selection settings affect only this transient HDEVINFO element.
   // InvokeOnce installs the selected new package; it is the sole install/init call.
   exactInf=Path.GetFullPath(exactInf);if(exactInf.Length>=260||!File.Exists(exactInf)||Hash(exactInf)!="3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb")throw new Exception("Exact new signed INF bytes/path required");
   // DI_ENUMSINGLEINF|DI_QUIETINSTALL. New package must copy its files;
   // installed-only and old no-copy policy are explicitly cleared.
   // ALLOWEXCLUDEDDRVS is required for this PnP INF ExcludeFromSelect=*;
   // selection remains exact-source, compatible-device, version/section/hash bound.
   Parameters.Flags=SelectionFlags(Parameters.Flags);
   Parameters.FlagsEx=SelectionFlagsEx(Parameters.FlagsEx);Parameters.DriverPath=exactInf;
   Check(SetupDiSetDeviceInstallParamsW(h,ref d,ref Parameters),"Set exact single-INF/quiet/copy-enabled local policy");
   Check(SetupDiBuildDriverInfoList(h,ref d,2),"Build ONLY exact single-INF compatible list");list=true;
   driver=new DRIVER();driver.cbSize=1568;Check(SetupDiEnumDriverInfoW(h,ref d,2,0,ref driver),"Single-INF compatible driver0");
   DRIVER next=new DRIVER();next.cbSize=1568;if(SetupDiEnumDriverInfoW(h,ref d,2,1,ref next)||Marshal.GetLastWin32Error()!=259)throw new Exception("Exactly one single-INF compatible driver required");DriverCount=1;
   if(driver.DriverVersion!=0x00010000117e0898UL)throw new Exception("Exact matched version1.0.4478.2200 required");
   uint need;bool first=SetupDiGetDriverInfoDetailW(h,ref d,ref driver,IntPtr.Zero,0,out need);int err=Marshal.GetLastWin32Error();if(first||err!=122||need<1584||need>65536)throw new Exception("Bounded driver detail size query required");
   IntPtr data=Marshal.AllocHGlobal((int)need);try{Marshal.WriteInt32(data,1584);Check(SetupDiGetDriverInfoDetailW(h,ref d,ref driver,data,need,out need),"Driver detail");SelectedDetail=(DETAIL)Marshal.PtrToStructure(data,typeof(DETAIL));}finally{Marshal.FreeHGlobal(data);}
   string inf=Path.GetFullPath(SelectedDetail.InfFile);
   if(!String.Equals(inf,exactInf,StringComparison.OrdinalIgnoreCase))CandidateError="Single-INF detail path differs from exact source";
   if(CandidateError==null)InfSha256=Hash(inf);
   if(CandidateError==null && (InfSha256!="3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb"||!String.Equals(SelectedDetail.Section,"QcWlan_BERYLLIUM.ndi",StringComparison.OrdinalIgnoreCase)))CandidateError="Exact new signed INF/generic base section not matched: "+SelectedDetail.Section;
   if(CandidateError==null){uint line;IntPtr hinf=SetupOpenInfFileW(inf,IntPtr.Zero,2,out line);Check(hinf!=new IntPtr(-1),"Open exact signed INF for architecture resolution");try{StringBuilder actual=new StringBuilder(256);uint required;Check(SetupDiGetActualSectionToInstallExW(hinf,SelectedDetail.Section,IntPtr.Zero,actual,256,out required,IntPtr.Zero,IntPtr.Zero),"Resolve local native architecture section");if(required<1||required>256)throw new Exception("Bounded resolved section required");ResolvedSection=actual.ToString();if(!String.Equals(ResolvedSection,"QcWlan_BERYLLIUM.ndi.NTarm64",StringComparison.OrdinalIgnoreCase))CandidateError="Unexpected resolved architecture section: "+ResolvedSection;}finally{SetupCloseInfFile(hinf);}}

   Check(SetupDiSetSelectedDriverW(h,ref d,ref driver),"Select exact new signed single-INF node in local set");
   Check(SetupDiGetDeviceInstallParamsW(h,ref d,ref Parameters),"Policy readback");if((Parameters.Flags&0x00810000U)!=0x00810000U||(Parameters.Flags&0x01000000U)!=0||(Parameters.FlagsEx&0x04000000U)!=0||(Parameters.FlagsEx&0x00000800U)==0||!String.Equals(Path.GetFullPath(Parameters.DriverPath),exactInf,StringComparison.OrdinalIgnoreCase))throw new Exception("Local policy did not persist");CurrentInstallProblem();
  }catch{Dispose();throw;}
 }
 public object InvokeOnce(){if(CandidateError!=null)throw new Exception(CandidateError);if(attempted)throw new Exception("No repeated install call");CurrentInstallProblem();attempted=true;bool reboot;bool ok=DiInstallDevice(IntPtr.Zero,h,ref d,ref driver,0,out reboot);int error=ok?0:Marshal.GetLastWin32Error();return new {success=ok,error=error,NeedReboot=reboot,calls=1,Flags=0,explicit_matched_single_INF=true,automatic_reboot=false};}
 public void Dispose(){if(h!=new IntPtr(-1)){if(list)SetupDiDestroyDriverInfoList(h,ref d,2);SetupDiDestroyDeviceInfoList(h);h=new IntPtr(-1);}}
}
