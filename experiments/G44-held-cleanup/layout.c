#include <stdio.h>
#include <stddef.h>
#include "g44_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G44_TOUCH_RESULT),sizeof(G44_TRIAL_RESULT),offsetof(G44_TRIAL_RESULT,Touch),offsetof(G44_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G44_TOUCH_RESULT,BeforePins),offsetof(G44_TOUCH_RESULT,LengthsBefore),offsetof(G44_TOUCH_RESULT,CommandHistory),offsetof(G44_TOUCH_RESULT,WaitCounts),offsetof(G44_TOUCH_RESULT,Tx),offsetof(G44_TOUCH_RESULT,Rx),offsetof(G44_TOUCH_RESULT,Version),offsetof(G44_TOUCH_RESULT,Trace));return 0;}
