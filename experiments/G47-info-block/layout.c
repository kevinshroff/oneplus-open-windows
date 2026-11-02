#include <stdio.h>
#include <stddef.h>
#include "g47_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G47_TOUCH_RESULT),sizeof(G47_TRIAL_RESULT),offsetof(G47_TRIAL_RESULT,Touch),offsetof(G47_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G47_TOUCH_RESULT,BeforePins),offsetof(G47_TOUCH_RESULT,LengthsBefore),offsetof(G47_TOUCH_RESULT,CommandHistory),offsetof(G47_TOUCH_RESULT,WaitCounts),offsetof(G47_TOUCH_RESULT,Tx),offsetof(G47_TOUCH_RESULT,Rx),offsetof(G47_TOUCH_RESULT,Version),offsetof(G47_TOUCH_RESULT,Trace));return 0;}
