#include <stdio.h>
#include <stddef.h>
#include "g43_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G43_TOUCH_RESULT),sizeof(G43_TRIAL_RESULT),offsetof(G43_TRIAL_RESULT,Touch),offsetof(G43_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G43_TOUCH_RESULT,BeforePins),offsetof(G43_TOUCH_RESULT,LengthsBefore),offsetof(G43_TOUCH_RESULT,CommandHistory),offsetof(G43_TOUCH_RESULT,WaitCounts),offsetof(G43_TOUCH_RESULT,Tx),offsetof(G43_TOUCH_RESULT,Rx),offsetof(G43_TOUCH_RESULT,Version),offsetof(G43_TOUCH_RESULT,Trace));return 0;}
