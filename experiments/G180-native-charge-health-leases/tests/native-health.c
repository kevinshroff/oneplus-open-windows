/* Appended native-adapter scenarios. Provider is an explicit mock boundary;
 * actual provider transport is separately exercised by its WDF model. */
static void*WorkerThreadMain(void*p){(void)p;RunWorker();return NULL;}
static void BlockWorker(void)
{
 HoldWorker=1;atomic_store(&ProviderBlock,1);atomic_store(&ProviderEntered,0);
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&Response->LastResult==4&&Owner->Data.HealthBusy);
 assert(!pthread_create(&WorkThread,NULL,WorkerThreadMain,NULL));WorkThreadActive=1;
 while(!atomic_load(&ProviderEntered))sched_yield();
}
static void ReleaseWorker(void)
{
 atomic_store(&ProviderBlock,0);assert(WorkThreadActive&&!pthread_join(WorkThread,NULL));WorkThreadActive=0;HoldWorker=0;
}
static void UntilOff(void){for(unsigned i=0;i<100&&Owner->Data.State.BatchActive;i++)Tick();assert(Owner->Data.State.PulseDisableAcked&&Peer.Enables==1&&Peer.Disables==2);}
static void*UnloadThreadMain(void*p){(void)p;ClnUnload((void*)1);return NULL;}
static void HealthIntegration(void)
{
 Reset();Ready();NativeFv(2);NativeEnabled(3);uint64_t prior=Owner->Data.State.PulseUntilUs,hard=Owner->Data.State.PulseHardUntilUs;
 Clock=(Owner->Data.State.LastHealthLeaseUs+30000000)*10;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&Response->LastResult==1&&!Owner->Data.HealthBusy);
 assert(Owner->Data.Health.Accepted==3&&Owner->Data.State.HealthLeaseRenewals==1&&Owner->Data.State.PulseUntilUs>prior&&Owner->Data.State.PulseHardUntilUs==hard);
 Save("health-renewed.bin");unsigned calls=ProviderCalls;uint64_t until=Owner->Data.State.PulseUntilUs;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&ProviderCalls==calls&&Owner->Data.State.PulseUntilUs==until);
 assert(Cmd(CLN_SAMPLE,4)==STATUS_INVALID_DEVICE_STATE);
 Clock=until*10;UntilOff();Closed(5);Finish();
 /* A blocked provider cannot hold the automatic timer's device lock. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);BlockWorker();until=Owner->Data.State.PulseUntilUs;
 Save("health-pending.bin");Clock=until*10;UntilOff();Save("health-expired-pending.bin");assert(Owner->Data.HealthBusy&&Owner->Data.State.HealthLeaseRenewals==0);
 ReleaseWorker();assert(Owner->Data.Health.Fault==CH_CONTROL_REJECTED&&Owner->Data.State.PulseUntilUs==until&&Owner->Data.Health.Accepted==2&&!Owner->Data.ProviderUncertain);
 assert(Peer.Enables==1&&Peer.Disables==2);Closed(5);Finish();
 /* Stop and clean GLINK close can preempt acquisition. Retirement still waits
  * for the independent worker, and late success cannot re-enable hardware. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);BlockWorker();
 assert(Cmd(CLN_STOP_PULSE,5)==0);UntilOff();assert(Cmd(CLN_CLOSE,6)==0);
 for(unsigned i=0;i<100&&Owner->Data.Running;i++)Tick();
 assert(Owner->Data.Stopped&&!Owner->Data.MapsLive&&Owner->Data.HealthBusy&&!Owner->Data.SafeToUnload);
 Save("health-close-pending.bin");ReleaseWorker();Save("health-close-drained.bin");assert(Owner->Data.SafeToUnload&&!Owner->Data.HealthBusy&&Owner->Data.Health.Fault==CH_CONTROL_REJECTED&&Peer.Enables==1);Finish();
 /* Duplicate while queued does not enqueue or acquire twice. Another health
  * command is refused without consuming its ID; stop remains admissible. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);HoldWorker=1;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&Owner->Data.HealthBusy);calls=WorkEnqueues;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&WorkEnqueues==calls);
 assert(Cmd(CLN_HEALTH_RENEW,5)==STATUS_INVALID_DEVICE_STATE&&Owner->Data.LastCommandId==4);
 assert(Cmd(CLN_STOP_PULSE,5)==0);UntilOff();RunWorker();HoldWorker=0;
 assert(Owner->Data.Health.Fault==CH_CONTROL_REJECTED&&!Owner->Data.State.HealthLeaseRenewals);Closed(6);Finish();
 /* Malformed or inadmissible trusted health faults before control. */
 for(unsigned bad=1;bad<=4;bad++){
  Reset();Ready();ProviderBad=bad;assert(Cmd(CLN_BOARD_FV,2)==0&&Response->LastResult==3);
  if(bad==2)Save("health-precontrol-refused.bin");assert(Owner->Data.Health.Fault&&!Owner->Data.Health.Accepted&&!Peer.Sets&&!Owner->Data.State.BoardFvAttempted);
  calls=ProviderCalls;ProviderBad=0;assert(Cmd(CLN_BOARD_FV,3)==STATUS_INVALID_DEVICE_STATE&&ProviderCalls==calls);Closed(3);Finish();
 }
 Reset();Ready();NativeFv(2);NativeEnabled(3);ProviderBad=2;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&Response->LastResult==3&&Owner->Data.Health.Fault==CH_TEMPERATURE);UntilOff();Save("health-thermal-stop.bin");Closed(5);Finish();
 /* Provider transport uncertainty is sticky and separate from GLINK. Ordinary
  * deliberate unload would be refused. Fixture teardown invokes unload only
  * to free modeled memory; it is not an authorized native recovery method. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);ProviderFailure=1;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0&&Owner->Data.ProviderUncertain&&Owner->Data.Health.Fault==CH_PROVIDER_IO);UntilOff();
 assert(Cmd(CLN_CLOSE,5)==0);for(unsigned i=0;i<100&&Owner->Data.Running;i++)Tick();
 assert(!Owner->Data.MapsLive&&!Owner->Data.SafeToUnload&&Owner->Data.ProviderUncertain);Save("health-provider-uncertain-closed.bin");Finish();
 /* A queued worker is drained before free; stopped owner does no provider I/O. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);HoldWorker=1;calls=ProviderCalls;
 assert(Cmd(CLN_HEALTH_RENEW,4)==0);ClnUnload((void*)1);
 assert(!Owner&&!Timer&&!Device&&!HealthWork&&ProviderCalls==calls&&Freed==1&&WorkFlushes==1&&MapCount==UnmapCount);NativeCases++;
 /* An active provider callback must also drain before freeing owner/context.
  * Wait without holding the device lock, so its completion can acquire it. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);BlockWorker();pthread_t unload;
 assert(!pthread_create(&unload,NULL,UnloadThreadMain,NULL));
 while(!atomic_load(&WorkFlushEntered))sched_yield();
 atomic_store(&ProviderBlock,0);assert(!pthread_join(unload,NULL));
 assert(!Owner&&!Timer&&!Device&&!HealthWork&&!WorkThreadActive&&Freed==1&&MapCount==UnmapCount);NativeCases++;
 /* Repeated typed health admission extends only to the immutable hard cap. */
 Reset();Ready();NativeFv(2);NativeEnabled(3);uint64_t enabled=Owner->Data.State.LastHealthLeaseUs;hard=Owner->Data.State.PulseHardUntilUs;
 for(unsigned round=1;round<=29;round++){
  Clock=(enabled+(uint64_t)round*30000000)*10;
  assert(Cmd(CLN_HEALTH_RENEW,round+3)==0&&Response->LastResult==1&&!Owner->Data.Health.Fault);
  assert(Owner->Data.State.PulseHardUntilUs==hard&&Owner->Data.State.PulseUntilUs<=hard);
 }
 assert(Owner->Data.State.HealthLeaseRenewals==29&&Owner->Data.State.PulseUntilUs==hard);
 Save("health-hard-cap-active.bin");Clock=hard*10;UntilOff();Save("health-hard-cap-complete.bin");Closed(33);Finish();
}
