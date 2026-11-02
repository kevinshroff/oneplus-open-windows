#include <stdio.h>
#include <stddef.h>
#include "g39_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G39_TOUCH_RESULT),sizeof(G39_TRIAL_RESULT),offsetof(G39_TRIAL_RESULT,Touch),offsetof(G39_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G39_TOUCH_RESULT,BeforePins),offsetof(G39_TOUCH_RESULT,LengthsBefore),offsetof(G39_TOUCH_RESULT,CommandHistory),offsetof(G39_TOUCH_RESULT,WaitCounts),offsetof(G39_TOUCH_RESULT,Tx),offsetof(G39_TOUCH_RESULT,Rx),offsetof(G39_TOUCH_RESULT,Version),offsetof(G39_TOUCH_RESULT,Trace));return 0;}
