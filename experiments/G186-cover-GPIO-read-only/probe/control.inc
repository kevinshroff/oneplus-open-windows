VOID G186Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G186_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G186_IOCTL_STATUS&&code!=G186_IOCTL_READ&&code!=G186_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G186_ABI||in.Magic!=G186_MAGIC||in.Reserved||in.Count||(code==G186_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G186_IOCTL_STATUS?sizeof(G186_STATUS):sizeof(G186_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G186_IOCTL_STATUS)Status(output);
 else if(code==G186_IOCTL_RESULT){if(!InterlockedCompareExchange(&G186Ready,0,0)||G186Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G186Frozen,sizeof(*G186Frozen));}
 else{if(InterlockedCompareExchange(&G186Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G186Frozen,sizeof(*G186Frozen));Capture(G186Frozen,request,in.Nonce);RtlCopyMemory(output,G186Frozen,sizeof(*G186Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
