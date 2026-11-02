
static void Reset(void){assert(!C.Thread);if(C.ControlInitialized)assert(!pthread_mutex_destroy(&C.Control));memset(&C,0,sizeof(C));memset(&KernelResult,0,sizeof(KernelResult));memset(&Response,0,sizeof(Response));assert(!pthread_mutex_init(&C.Control,NULL));C.ControlInitialized=1;C.Result=&KernelResult;C.Handle=(void*)3;C.D0=C.Started=1;C.LastSubmit=STATUS_DEVICE_NOT_READY;AdmitCalls=Submits=Deletes=Frees=Starts=HandlesCreated=HandlesClosed=Joins=FailCreate=FailSubmit=HWQueries=0;Build=26300;Processors=8;Irql=0;FirmwareMatch=FullOS=1;StartReturn=0;InterlockedExchange(&HWCalls,0);InterlockedExchange(&HWEntered,0);InterlockedExchange(&AllowFinish,0);InterlockedExchange(&HoldThread,0);InterlockedExchange(&Scenario,0);InterlockedExchange(&PendingChecks,0);}
static Request Call(ULONG code,size_t input,size_t output,G98HID_REQUEST*in){Request r={in,&Response,(void*)5,0,0,0,0};G98HIDControl((void*)2,&r,output,input,code);Cases++;return r;}
static void Entered(void){for(unsigned i=0;i<3000;i++){if(__atomic_load_n(&HWEntered,__ATOMIC_SEQ_CST))return;Nap();}assert(!"worker did not enter hardware");}
static void Done(void){for(unsigned i=0;i<3000;i++){if(Counter(&C.State)==G98_OWNER_DONE)return;Nap();}assert(!"worker did not finish");}
static void Final(unsigned outcome,unsigned reports){G98_SESSION q;SessionStatus(&C,&q);assert(q.State==G98_OWNER_DONE&&q.Starts==1&&q.Outcome==outcome&&q.ThreadJoined==1&&!C.Thread&&C.OwnerFile==NULL&&HandlesCreated==HandlesClosed&&Joins==HandlesCreated&&C.Live.StopAttempts==1&&Submits==reports);assert(q.EndUs>=q.BeginUs);}
int main(void){G98HID_REQUEST hw={16,1,G98_MAGIC},hid={16,1,G98HID_MAGIC};Request r;G98_SESSION session;
 const ULONG codes[]={G98HID_IOCTL_STATUS,G98HID_IOCTL_SESSION,G98HID_IOCTL_START,G98HID_IOCTL_STOP,G98_IOCTL_STATUS,G98_IOCTL_SNAPSHOT,G98_IOCTL_PMIC,G98_IOCTL_POWER};const size_t sizes[]={160,96,96,96,80,288,1728,969808};
 for(unsigned at=0;at<8;at++)for(unsigned bad=0;bad<9;bad++){
  Reset();G98HID_REQUEST q=at<4?hid:hw;size_t input=16,output=sizes[at];ULONG code=codes[at];
  if(bad==0)code=0;if(bad==1)input=15;if(bad==2)input=17;if(bad==3)q.Size=15;if(bad==4)q.Version=2;if(bad==5)q.Magic^=1;if(bad==6)q.Magic=at<4?G98_MAGIC:G98HID_MAGIC;if(bad==7)output--;if(bad==8)code=0x22e404;
  r=Call(code,input,output,&q);assert(r.Completed<0&&!r.Information&&!HWCalls&&!HWQueries&&!C.Starts&&!C.Thread);
 }

 const ULONG extra_codes[]={G98HID_IOCTL_RUN,G98HID_IOCTL_RUNTIME,G98HID_IOCTL_FAULT};const size_t extra_sizes[]={96,160,136};
 for(unsigned at=0;at<3;at++)for(unsigned bad=0;bad<7;bad++){Reset();G98HID_REQUEST q=hid;size_t input=16,output=extra_sizes[at];if(bad==0)q.Magic=G98_MAGIC;if(bad==1)q.Version++;if(bad==2)q.Size--;if(bad==3)input--;if(bad==4)input++;if(bad==5)output--;if(bad==6)q.Magic=0;r=Call(extra_codes[at],input,output,&q);assert(r.Completed<0&&!HWCalls&&!C.Thread&&!C.Starts);}
 Reset();r=Call(G98_IOCTL_POWER,16,sizeof(Response),&hw);assert(r.Completed==STATUS_DEVICE_NOT_READY&&!HWCalls&&!C.Starts);
 r=Call(G98HID_IOCTL_SESSION,16,96,&hid);assert(!r.Completed&&r.Information==96);memcpy(&session,&Response,96);assert(session.Size==96&&session.State==0&&!session.Starts);
 Reset();r=Call(G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed&&r.Information==96);memset(&Response,0xa5,sizeof(Response));Done();r=Call(G98_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&r.Information==sizeof(Response)&&Response.Trial.Touch.Poll.Cycles==G98_NATIVE_CYCLES);Final(G98_OUTCOME_COMPLETE,4);assert(C.LiveComplete&&!C.Live.Accepted.Mask);
 r=Call(G98HID_IOCTL_START,16,96,&hid);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&C.Starts==1&&HWCalls==1);
 for(unsigned play=0;play<2;play++)for(unsigned stop=1;stop<=5;stop++){
  Reset();InterlockedExchange(&Scenario,1);r=Call(play?G98HID_IOCTL_PLAY:G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();assert(C.CycleLimit==(play?G98_PLAY_CYCLES:G98_NATIVE_CYCLES));
  r=Call(G98HID_IOCTL_STATUS,16,160,&hid);assert(!r.Completed);G98HID_STATUS source;memcpy(&source,&Response,160);assert(source.ReportsAccepted==1&&source.ReportsSubmitted==1&&!source.AcceptedMask&&!source.StopAttempts); // live counts, frozen masks
  unsigned queries=HWQueries;r=Call(G98_IOCTL_SNAPSHOT,16,288,&hw);assert(r.Completed==STATUS_DEVICE_BUSY&&HWQueries==queries);r=Call(G98_IOCTL_PMIC,16,1728,&hw);assert(r.Completed==STATUS_DEVICE_BUSY&&HWQueries==queries);
  G98HIDFileCleanup((void*)6);assert(C.Thread&&C.State==G98_OWNER_RUNNING); // a different file cannot own this session
  if(stop==1){r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);}
  if(stop==2)G98HIDFileCleanup((void*)5);
  if(stop==3){assert(!G98HIDSuspend((void*)1)&&C.Inhibit);assert(!G98HIDD0Exit((void*)1,0)&&!C.D0);assert(!G98HIDD0Entry((void*)1,0)&&!G98HIDRestart((void*)1));}
  if(stop==4){assert(!G98HIDD0Exit((void*)1,0)&&!C.D0);assert(!G98HIDD0Entry((void*)1,0));}
  if(stop==5)G98HIDCleanup((void*)1);
  Final(G98_OUTCOME_CANCELLED,2);assert(!C.LiveComplete&&C.Live.StopAccepted&&!C.Live.Accepted.Mask&&C.StopSeen&&(unsigned)C.StopReason==stop);
  assert(Reports[0][1]&1&&!(Reports[1][1]&1)&&!memcmp(Reports[0]+2,Reports[1]+2,5)); // cleanup UP retains accepted ID/coordinates
  if(stop!=5){r=Call(G98_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&Response.Trial.Touch.Code==G98_TOUCH_CANCELLED);G98HIDCleanup((void*)1);}assert(Deletes==1&&Frees==1);
 }
 Reset();r=Call(G98HID_IOCTL_PLAY,16,96,&hid);assert(!r.Completed);Done();r=Call(G98_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&Response.Trial.Touch.Poll.Cycles==G98_PLAY_CYCLES);Final(G98_OUTCOME_COMPLETE,4);r=Call(G98HID_IOCTL_PLAY,16,96,&hid);assert(r.Completed==STATUS_QUOTA_EXCEEDED);
 Reset();InterlockedExchange(&HoldThread,1);r=Call(G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed);G98HIDFileCleanup((void*)5);Final(G98_OUTCOME_CANCELLED_BEFORE_HARDWARE,0);assert(!HWCalls&&!C.HardwareCalls&&C.Result->Trial.Power.Code==1010);
 Reset();FailCreate=1;r=Call(G98HID_IOCTL_START,16,96,&hid);assert(r.Completed==STATUS_INSUFFICIENT_RESOURCES&&!C.Thread&&!HWCalls&&!C.ResultReady&&C.Starts==1&&C.Outcome==G98_OUTCOME_FAILED);G98HIDCleanup((void*)1);assert(Frees==1&&Deletes==1);
 for(unsigned bad=0;bad<9;bad++){
  Reset();if(bad==0)FirmwareMatch=0;if(bad==1)Processors=7;if(bad==2)Build=26101;if(bad==3)Irql=2;if(bad==4)C.D0=0;if(bad==5)C.Started=0;if(bad==6)C.Inhibit=1;if(bad==7)C.Removed=1;if(bad==8)FullOS=0;
  r=Call(G98HID_IOCTL_START,16,96,&hid);assert(r.Completed<0&&!C.Thread&&!C.Starts&&!HWCalls);
 }
 Reset();InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();G98HIDSurprise((void*)1);Final(G98_OUTCOME_FAILED,2);assert(C.Removed&&C.Inhibit&&!C.Result->Trial.Power.Restored&&!C.Result->Trial.SafeRelease);
 for(unsigned fail=1;fail<=2;fail++){
  Reset();FailSubmit=fail;InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&C.Outcome==G98_OUTCOME_FAILED&&!C.LiveComplete);assert(C.Live.Error&&(fail==1?!C.Live.Accepted.Mask:C.Live.Accepted.Mask==1));G98HIDCleanup((void*)1);
 }
 for(unsigned repeat=0;repeat<100;repeat++){
  Reset();InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_START,16,96,&hid);assert(!r.Completed);Entered();if(repeat&1)InterlockedExchange(&AllowFinish,1);r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&C.State==G98_OWNER_DONE&&C.Starts==1&&!C.Live.Accepted.Mask&&!C.Thread&&HandlesClosed==1);assert(C.Outcome==G98_OUTCOME_CANCELLED||C.Outcome==G98_OUTCOME_COMPLETE);G98HIDCleanup((void*)1);
 }

 Reset();InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Entered();assert(C.Persistent&&C.OwnerFile==NULL);r=Call(G98HID_IOCTL_RUNTIME,16,160,&hid);G98_RUNTIME runtime;memcpy(&runtime,&Response,160);assert(!r.Completed&&runtime.Size==160&&runtime.Cycles==1&&runtime.ReportsAccepted==1&&runtime.OwnerStarts==1);
 G98HIDFileCleanup((void*)5);assert(C.Thread&&C.State==G98_OWNER_RUNNING);assert(!G98HIDSuspend((void*)1));Final(G98_OUTCOME_CANCELLED,2);assert(!G98HIDD0Exit((void*)1,0)&&!C.D0);assert(!G98HIDD0Entry((void*)1,0));InterlockedExchange(&HWEntered,0);assert(!G98HIDRestart((void*)1));Entered();assert(C.State==G98_OWNER_RUNNING&&C.Persistent&&TimeValue(&C.OwnerStarts)==2);r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);Final(G98_OUTCOME_CANCELLED,4);assert(!G98HIDD0Exit((void*)1,0)&&!G98HIDD0Entry((void*)1,0)&&!G98HIDRestart((void*)1));assert(C.State==G98_OWNER_DONE&&TimeValue(&C.OwnerStarts)==2);G98HIDCleanup((void*)1);
 Reset();InterlockedExchange(&HoldThread,1);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&C.Outcome==G98_OUTCOME_CANCELLED_BEFORE_HARDWARE&&!HWCalls);InterlockedExchange(&HoldThread,0);InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Entered();r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);Final(G98_OUTCOME_CANCELLED,2);G98HIDCleanup((void*)1);

 Reset();InterlockedExchange(&Scenario,2);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Entered();assert(HWCalls==4&&TimeValue(&C.Recoveries)==3&&Counter(&C.FaultReady));r=Call(G98HID_IOCTL_FAULT,16,136,&hid);G98_FAULT fault;memcpy(&fault,&Response,136);assert(!r.Completed&&fault.Present&&fault.PollCode==G98_POLL_DECODE&&fault.FrameError==G98_BAD_BODY&&fault.ReadBytes==26&&!memcmp(fault.Bytes,G98TESTBadBody,26));r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);Final(G98_OUTCOME_CANCELLED,8);G98HIDCleanup((void*)1);
 for(unsigned scenario=3;scenario<=5;scenario++){Reset();InterlockedExchange(&Scenario,scenario);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Done();r=Call(G98_IOCTL_POWER,16,sizeof(Response),&hw);assert(!r.Completed&&C.Outcome==G98_OUTCOME_FAILED&&TimeValue(&C.Recoveries)==(scenario==5?3:0)&&HWCalls==(scenario==5?4:1));if(scenario==3){r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(r.Completed==STATUS_DEVICE_NOT_READY&&HWCalls==1);}G98HIDCleanup((void*)1);}
 Reset();InterlockedExchange(&Scenario,6);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Entered();r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed&&HWCalls==1&&TimeValue(&C.Recoveries)==0);Final(G98_OUTCOME_CANCELLED,2);G98HIDCleanup((void*)1);
 Reset();InterlockedExchange(&Scenario,7);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Done();assert(!HWCalls&&C.Result->Trial.Power.Code==1011&&C.Outcome==G98_OUTCOME_FAILED);G98HIDCleanup((void*)1);
 Reset();C.Started=0;assert(!G98HIDIoInit((void*)1)&&C.Started&&Starts==1);G98HIDCleanup((void*)1);G98HIDCleanup((void*)1);assert(Deletes==1&&Frees==1);

 /* Actual deferred admission: metadata first, no observer/trial until ready. */
 Reset();G98HID_STATUS gate;Build=26100;FullOS=2;assert(Admission(&C,&gate)==2&&gate.KernelBuild==26100&&!HWCalls);Cases++;
 FullOS=0;assert(!Admission(&C,NULL));Cases++;FullOS=1;assert(Admission(&C,NULL)==2);Cases++;
 Build=26101;assert(!Admission(&C,NULL));Cases++;
 Build=26300;assert(Admission(&C,NULL)==1);Cases++;FullOS=2;assert(Admission(&C,NULL)==2);Cases++;
 Reset();FullOS=2;r=Call(G98HID_IOCTL_START,16,96,&hid);assert(r.Completed==STATUS_NOT_SUPPORTED&&!C.Thread&&!HWCalls);Cases++;
 Reset();InterlockedExchange(&PendingChecks,20);InterlockedExchange(&Scenario,1);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Entered();assert(!Counter(&PendingChecks)&&HWCalls==1&&AdmitCalls==1);r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);Final(G98_OUTCOME_CANCELLED,2);G98HIDCleanup((void*)1);
 Reset();InterlockedExchange(&PendingChecks,1000);r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Nap();assert(!HWCalls&&C.State==G98_OWNER_QUEUED);r=Call(G98HID_IOCTL_STOP,16,96,&hid);assert(!r.Completed);Final(G98_OUTCOME_CANCELLED_BEFORE_HARDWARE,0);assert(!C.HardwareCalls&&!AdmitCalls);G98HIDCleanup((void*)1);
 Reset();FullOS=2;r=Call(G98HID_IOCTL_RUN,16,96,&hid);assert(!r.Completed);Done();assert(!HWCalls&&!C.HardwareCalls&&!AdmitCalls&&C.Outcome==G98_OUTCOME_FAILED&&C.Result->Trial.Power.Code==1012);G98HIDCleanup((void*)1);Cases++;

 printf("{\"passed\":true,\"IO_cases\":%u,\"real_pthread_worker_and_join\":true,\"actual_root_callbacks\":true,\"eight_IOCTL_guards\":true,\"result_uses_driver_owned_buffer\":true,\"close_suspend_D0_cleanup_cancel_before_hardware\":true,\"surprise_removal_denies_followup_hardware\":true,\"all100_finish_stop_races\":true,\"verified_persistent_rearm\":true,\"hardware_and_WDF_VHF_services_modeled\":true}\n",Cases);return 0;
}
