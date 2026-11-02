#include <stdio.h>
#include <stddef.h>
#include "g45_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G45_TOUCH_RESULT),sizeof(G45_TRIAL_RESULT),offsetof(G45_TRIAL_RESULT,Touch),offsetof(G45_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G45_TOUCH_RESULT,BeforePins),offsetof(G45_TOUCH_RESULT,LengthsBefore),offsetof(G45_TOUCH_RESULT,CommandHistory),offsetof(G45_TOUCH_RESULT,WaitCounts),offsetof(G45_TOUCH_RESULT,Tx),offsetof(G45_TOUCH_RESULT,Rx),offsetof(G45_TOUCH_RESULT,Version),offsetof(G45_TOUCH_RESULT,Trace));return 0;}
