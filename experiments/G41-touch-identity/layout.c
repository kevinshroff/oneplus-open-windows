#include <stdio.h>
#include <stddef.h>
#include "g41_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G41_TOUCH_RESULT),sizeof(G41_TRIAL_RESULT),offsetof(G41_TRIAL_RESULT,Touch),offsetof(G41_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G41_TOUCH_RESULT,BeforePins),offsetof(G41_TOUCH_RESULT,LengthsBefore),offsetof(G41_TOUCH_RESULT,CommandHistory),offsetof(G41_TOUCH_RESULT,WaitCounts),offsetof(G41_TOUCH_RESULT,Tx),offsetof(G41_TOUCH_RESULT,Rx),offsetof(G41_TOUCH_RESULT,Version),offsetof(G41_TOUCH_RESULT,Trace));return 0;}
