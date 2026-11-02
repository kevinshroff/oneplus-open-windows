using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Collections.Generic;
public static class G1333ScanAndCache {
 [StructLayout(LayoutKind.Sequential)]struct N {public uint source,code;public Guid id;public uint bytes;public IntPtr data;}
 [StructLayout(LayoutKind.Sequential)]struct SSID {public uint length;[MarshalAs(UnmanagedType.ByValArray,SizeConst=32)]public byte[] bytes;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct NETWORK {
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string profile;
  public SSID ssid;public uint bssType,bssids;[MarshalAs(UnmanagedType.Bool)]public bool connectable;public uint notConnectableReason,phyCount;
  [MarshalAs(UnmanagedType.ByValArray,SizeConst=8)]public uint[] phyTypes;
  [MarshalAs(UnmanagedType.Bool)]public bool morePhyTypes;public uint quality;[MarshalAs(UnmanagedType.Bool)]public bool security;public uint auth,cipher,flags,reserved;
 }
 delegate void Callback(ref N n,IntPtr context);
 const string WLAN="C:\\Windows\\System32\\wlanapi.dll";
 [DllImport(WLAN)]static extern uint WlanOpenHandle(uint v,IntPtr r,out uint n,out IntPtr h);
 [DllImport(WLAN)]static extern uint WlanCloseHandle(IntPtr h,IntPtr r);
 [DllImport(WLAN)]static extern uint WlanRegisterNotification(IntPtr h,uint source,[MarshalAs(UnmanagedType.Bool)]bool duplicate,Callback cb,IntPtr ctx,IntPtr r,out uint previous);
 [DllImport(WLAN)]static extern uint WlanScan(IntPtr h,ref Guid id,IntPtr ssid,IntPtr ie,IntPtr r);
 [DllImport(WLAN)]static extern uint WlanGetAvailableNetworkList(IntPtr h,ref Guid id,uint flags,IntPtr reserved,out IntPtr list);
 [DllImport(WLAN)]static extern void WlanFreeMemory(IntPtr p);
 static bool attempted;
 public static object LayoutOnly(){return new {pointer_bytes=IntPtr.Size,notification_bytes=Marshal.SizeOf(typeof(N)),cached_network_bytes=Marshal.SizeOf(typeof(NETWORK)),native_calls=0};}
 public static object ScanOnce(Guid id){
  if(IntPtr.Size!=8||Marshal.SizeOf(typeof(N))!=40)throw new Exception("Native64 notification layout required");
  if(attempted)throw new Exception("No repeated explicit scan");attempted=true;
  IntPtr h;uint v,r=WlanOpenHandle(2,IntPtr.Zero,out v,out h);if(r!=0)throw new Exception("Open WLAN "+r);
  using(var done=new ManualResetEvent(false)){uint code=0,reason=0,previous;Callback cb=delegate(ref N n,IntPtr c){if(n.source==8&&n.id==id&&(n.code==7||n.code==8)){code=n.code;if(n.code==8&&n.bytes>=4&&n.data!=IntPtr.Zero)reason=unchecked((uint)Marshal.ReadInt32(n.data));done.Set();}};
   try{r=WlanRegisterNotification(h,8,false,cb,IntPtr.Zero,IntPtr.Zero,out previous);if(r!=0)throw new Exception("Register ACM "+r);r=WlanScan(h,ref id,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);bool notified=r==0&&done.WaitOne(10000);return new {scanRequestResult=r,notificationReceived=notified,notificationCode=code,scan_complete_code=7,scan_fail_code=8,failureReason=reason,requests=1,scanOnly=true,notification_interface_only_not_request_correlated=true};}
   finally{WlanRegisterNotification(h,0,false,null,IntPtr.Zero,IntPtr.Zero,out previous);WlanCloseHandle(h,IntPtr.Zero);GC.KeepAlive(cb);}
  }
 }
 public static object CachedList(Guid id){
  if(IntPtr.Size!=8||Marshal.SizeOf(typeof(NETWORK))!=628)throw new Exception("Exact cached-network layout required");
  IntPtr h,list=IntPtr.Zero;uint version;uint opened=WlanOpenHandle(2,IntPtr.Zero,out version,out h);if(opened!=0)return new {openResult=opened,queryResult=(uint?)null,cachedOnly=true,queryRequests=0};
  try{uint result=WlanGetAvailableNetworkList(h,ref id,0,IntPtr.Zero,out list);if(result!=0||list==IntPtr.Zero)return new {openResult=opened,queryResult=result,cachedOnly=true,queryRequests=1};
   uint count=unchecked((uint)Marshal.ReadInt32(list));if(count>1024)throw new Exception("Bounded cached-list count required");var networks=new List<object>();
   for(uint i=0;i<count;i++){IntPtr p=IntPtr.Add(list,checked(8+(int)i*628));NETWORK n=(NETWORK)Marshal.PtrToStructure(p,typeof(NETWORK));if(n.ssid.length>32||n.quality>100)throw new Exception("Cached record bounds");byte[] ssid=new byte[n.ssid.length];Array.Copy(n.ssid.bytes,ssid,ssid.Length);networks.Add(new {ssid_utf8=Encoding.UTF8.GetString(ssid),ssid_base64=Convert.ToBase64String(ssid),profile=n.profile,quality=n.quality,connectable=n.connectable,notConnectableReason=n.notConnectableReason,security=n.security,auth=n.auth,cipher=n.cipher,bssids=n.bssids});}
   return new {openResult=opened,queryResult=result,queryRequests=1,cachedOnly=true,additional_scan_requests=0,availableNetworkCount=count,networks=networks.ToArray(),explicit_scan_correlation_established=false};
  }finally{if(list!=IntPtr.Zero)WlanFreeMemory(list);WlanCloseHandle(h,IntPtr.Zero);}
 }
}
