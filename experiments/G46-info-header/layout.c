#include <stdio.h>
#include <stddef.h>
#include "g46_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G46_TOUCH_RESULT),sizeof(G46_TRIAL_RESULT),offsetof(G46_TRIAL_RESULT,Touch),offsetof(G46_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G46_TOUCH_RESULT,BeforePins),offsetof(G46_TOUCH_RESULT,LengthsBefore),offsetof(G46_TOUCH_RESULT,CommandHistory),offsetof(G46_TOUCH_RESULT,WaitCounts),offsetof(G46_TOUCH_RESULT,Tx),offsetof(G46_TOUCH_RESULT,Rx),offsetof(G46_TOUCH_RESULT,Version),offsetof(G46_TOUCH_RESULT,Trace));return 0;}
