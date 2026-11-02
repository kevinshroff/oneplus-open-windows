VOID G167Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G167_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G167_IOCTL_STATUS&&code!=G167_IOCTL_READ&&code!=G167_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G167_ABI||in.Magic!=G167_MAGIC||in.Reserved||in.Count||(code==G167_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G167_IOCTL_STATUS?sizeof(G167_STATUS):sizeof(G167_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G167_IOCTL_STATUS)Status(output);
 else if(code==G167_IOCTL_RESULT){if(!InterlockedCompareExchange(&G167Ready,0,0)||G167Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G167Frozen,sizeof(*G167Frozen));}
 else{if(InterlockedCompareExchange(&G167Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G167Frozen,sizeof(*G167Frozen));Capture(G167Frozen,request,in.Nonce);RtlCopyMemory(output,G167Frozen,sizeof(*G167Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
