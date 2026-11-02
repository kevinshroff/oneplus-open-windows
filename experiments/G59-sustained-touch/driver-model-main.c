
static void Reset(void){assert(!C.Thread);if(C.ControlInitialized)assert(!pthread_mutex_destroy(&C.Control));memset(&C,0,sizeof(C));memset(&KernelResult,0,sizeof(KernelResult));memset(&Response,0,sizeof(Response));assert(!pthread_mutex_init(&C.Control,NULL));C.ControlInitialized=1;C.Result=&KernelResult;C.Handle=(void*)3;C.D0=C.Started=1;C.LastSubmit=STATUS_DEVICE_NOT_READY;Submits=Deletes=Frees=Starts=HandlesCreated=HandlesClosed=Joins=FailCreate=FailSubmit=HWQueries=0;Build=26100;Processors=8;Irql=0;FirmwareMatch=1;StartReturn=0;InterlockedExchange(&HWCalls,0);InterlockedExchange(&HWEntered,0);InterlockedExchange(&AllowFinish,0);InterlockedExchange(&HoldThread,0);InterlockedExchange(&Scenario,0);}
static Request Call(ULONG code,size_t input,size_t output,G59HID_REQUEST*in){Request r={in,&Response,(void*)5,0,0,0,0};G59HIDControl((void*)2,&r,output,input,code);Cases++;return r;}
static void Entered(void){for(unsigned i=0;i<3000;i++){if(__atomic_load_n(&HWEntered,__ATOMIC_SEQ_CST))return;Nap();}assert(!"worker did not enter hardware");}
static void Done(void){for(unsigned i=0;i<3000;i++){if(Counter(&C.State)==G59_OWNER_DONE)return;Nap();}assert(!"worker did not finish");}
static void Final(unsigned outcome,unsigned reports){G59_SESSION q;SessionStatus(&C,&q);assert(q.State==G59_OWNER_DONE&&q.Starts==1&&q.Outcome==outcome&&q.ThreadJoined==1&&!C.Thread&&C.OwnerFile==NULL&&HandlesCreated==HandlesClosed&&Joins==HandlesCreated&&C.Live.StopAttempts==1&&Submits==reports);assert(q.EndUs>=q.BeginUs);}
int main(void){G59HID_REQUEST hw={16,1,G59_MAGIC},hid={16,1,G59HID_MAGIC};Request r;G59_SESSION session;
 const ULONG codes[]={G59HID_IOCTL_STATUS,G59HID_IOCTL_SESSION,G59HID_IOCTL_START,G59HID_IOCTL_STOP,G59_IOCTL_STATUS,G59_IOCTL_SNAPSHOT,G59_IOCTL_PMIC,G59_IOCTL_POWER};const size_t sizes[]={160,96,96,96,80,288,1728,959896};
 for(unsigned at=0;at<8;at++)for(unsigned bad=0;bad<9;bad++){
  Reset();G59HID_REQUEST q=at<4?hid:hw;size_t input=16,output=sizes[at];ULONG code=codes[at];
  if(bad==0)code=0;if(bad==1)input=15;if(bad==2)input=17;if(bad==3)q.Size=15;if(bad==4)q.Version=2;if(bad==5)q.Magic^=1;if(bad==6)q.Magic=at<4?G59_MAGIC:G59HID_MAGIC;if(bad==7)output--;if(bad==8)code=0x22e404;
  r=Call(code,input,output,&q);assert(r.Completed<0&&!r.Information&&!HWCalls&&!HWQueries&&!C.Starts&&!C.Thread);
 }
 Reset();r=Call(G59_IOCTL_POWER,16,sizeof(Response),&hw);assert(r.Completed==STATUS_DEVICE_NOT_READY&&!HWCalls&&!C.Starts);
 r=Call(G59HID_IOCTL_SESSION,16,96,&hid);assert(!r.Completed&&r.Information==96);memcpy(&session,&Response,96);assert(session.Size==96&&session.State==0&&!session.Starts);
 Reset();r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed&&r.Information==96);memset(&Response,0xa5,sizeof(Response));Done();r=Call(G59_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&r.Information==sizeof(Response)&&Response.Trial.Touch.Poll.Cycles==G59_NATIVE_CYCLES);Final(G59_OUTCOME_COMPLETE,4);assert(C.LiveComplete&&!C.Live.Accepted.Mask);
 r=Call(G59HID_IOCTL_START,16,96,&hid);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&C.Starts==1&&HWCalls==1);
 for(unsigned stop=1;stop<=5;stop++){
  Reset();InterlockedExchange(&Scenario,1);r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();
  r=Call(G59HID_IOCTL_STATUS,16,160,&hid);assert(!r.Completed);G59HID_STATUS source;memcpy(&source,&Response,160);assert(!source.ReportsAccepted&&!source.AcceptedMask&&!source.StopAttempts); // frozen fields only
  unsigned queries=HWQueries;r=Call(G59_IOCTL_SNAPSHOT,16,288,&hw);assert(r.Completed==STATUS_DEVICE_BUSY&&HWQueries==queries);r=Call(G59_IOCTL_PMIC,16,1728,&hw);assert(r.Completed==STATUS_DEVICE_BUSY&&HWQueries==queries);
  G59HIDFileCleanup((void*)6);assert(C.Thread&&C.State==G59_OWNER_RUNNING); // a different file cannot own this session
  if(stop==1){r=Call(G59HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);}
  if(stop==2)G59HIDFileCleanup((void*)5);
  if(stop==3){assert(!G59HIDSuspend((void*)1)&&C.Inhibit);assert(!G59HIDD0Exit((void*)1,0)&&!C.D0);assert(!G59HIDD0Entry((void*)1,0)&&!G59HIDRestart((void*)1));}
  if(stop==4){assert(!G59HIDD0Exit((void*)1,0)&&!C.D0);assert(!G59HIDD0Entry((void*)1,0));}
  if(stop==5)G59HIDCleanup((void*)1);
  Final(G59_OUTCOME_CANCELLED,2);assert(!C.LiveComplete&&C.Live.StopAccepted&&!C.Live.Accepted.Mask&&C.StopSeen&&(unsigned)C.StopReason==stop);
  assert(Reports[0][1]&1&&!(Reports[1][1]&1)&&!memcmp(Reports[0]+2,Reports[1]+2,5)); // cleanup UP retains accepted ID/coordinates
  if(stop!=5){r=Call(G59_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&Response.Trial.Touch.Code==G59_TOUCH_CANCELLED);G59HIDCleanup((void*)1);}assert(Deletes==1&&Frees==1);
 }
 Reset();InterlockedExchange(&HoldThread,1);r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed);G59HIDFileCleanup((void*)5);Final(G59_OUTCOME_CANCELLED_BEFORE_HARDWARE,0);assert(!HWCalls&&!C.HardwareCalls&&C.Result->Trial.Power.Code==1010);
 Reset();FailCreate=1;r=Call(G59HID_IOCTL_START,16,96,&hid);assert(r.Completed==STATUS_INSUFFICIENT_RESOURCES&&!C.Thread&&!HWCalls&&!C.ResultReady&&C.Starts==1&&C.Outcome==G59_OUTCOME_FAILED);G59HIDCleanup((void*)1);assert(Frees==1&&Deletes==1);
 for(unsigned bad=0;bad<8;bad++){
  Reset();if(bad==0)FirmwareMatch=0;if(bad==1)Processors=7;if(bad==2)Build=26101;if(bad==3)Irql=2;if(bad==4)C.D0=0;if(bad==5)C.Started=0;if(bad==6)C.Inhibit=1;if(bad==7)C.Removed=1;
  r=Call(G59HID_IOCTL_START,16,96,&hid);assert(r.Completed<0&&!C.Thread&&!C.Starts&&!HWCalls);
 }
 Reset();InterlockedExchange(&Scenario,1);r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();G59HIDSurprise((void*)1);Final(G59_OUTCOME_FAILED,2);assert(C.Removed&&C.Inhibit&&!C.Result->Trial.Power.Restored&&!C.Result->Trial.SafeRelease);
 for(unsigned fail=1;fail<=2;fail++){
  Reset();FailSubmit=fail;InterlockedExchange(&Scenario,1);r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();r=Call(G59HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&C.Outcome==G59_OUTCOME_FAILED&&!C.LiveComplete);assert(C.Live.Error&&(fail==1?!C.Live.Accepted.Mask:C.Live.Accepted.Mask==1));G59HIDCleanup((void*)1);
 }
 for(unsigned repeat=0;repeat<100;repeat++){
  Reset();InterlockedExchange(&Scenario,1);r=Call(G59HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();if(repeat&1)InterlockedExchange(&AllowFinish,1);r=Call(G59HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&C.State==G59_OWNER_DONE&&C.Starts==1&&!C.Live.Accepted.Mask&&!C.Thread&&HandlesClosed==1);assert(C.Outcome==G59_OUTCOME_CANCELLED||C.Outcome==G59_OUTCOME_COMPLETE);G59HIDCleanup((void*)1);
 }
 Reset();C.Started=0;assert(!G59HIDIoInit((void*)1)&&C.Started&&Starts==1);G59HIDCleanup((void*)1);G59HIDCleanup((void*)1);assert(Deletes==1&&Frees==1);
 printf("{\"passed\":true,\"IO_cases\":%u,\"real_pthread_worker_and_join\":true,\"actual_root_callbacks\":true,\"eight_IOCTL_guards\":true,\"result_uses_driver_owned_buffer\":true,\"close_suspend_D0_cleanup_cancel_before_hardware\":true,\"surprise_removal_denies_followup_hardware\":true,\"all100_finish_stop_races\":true,\"no_implicit_rearm\":true,\"hardware_and_WDF_VHF_services_modeled\":true}\n",Cases);return 0;
}
