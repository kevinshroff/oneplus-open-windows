#include <stdio.h>
#include <stddef.h>
#include "g40_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G40_TOUCH_RESULT),sizeof(G40_TRIAL_RESULT),offsetof(G40_TRIAL_RESULT,Touch),offsetof(G40_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G40_TOUCH_RESULT,BeforePins),offsetof(G40_TOUCH_RESULT,LengthsBefore),offsetof(G40_TOUCH_RESULT,CommandHistory),offsetof(G40_TOUCH_RESULT,WaitCounts),offsetof(G40_TOUCH_RESULT,Tx),offsetof(G40_TOUCH_RESULT,Rx),offsetof(G40_TOUCH_RESULT,Version),offsetof(G40_TOUCH_RESULT,Trace));return 0;}
