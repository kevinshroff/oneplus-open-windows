#include <stdio.h>
#include <stddef.h>
#include "g49_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G49_TOUCH_RESULT),sizeof(G49_TRIAL_RESULT),offsetof(G49_TRIAL_RESULT,Touch),offsetof(G49_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G49_TOUCH_RESULT,BeforePins),offsetof(G49_TOUCH_RESULT,LengthsBefore),offsetof(G49_TOUCH_RESULT,CommandHistory),offsetof(G49_TOUCH_RESULT,WaitCounts),offsetof(G49_TOUCH_RESULT,Tx),offsetof(G49_TOUCH_RESULT,Rx),offsetof(G49_TOUCH_RESULT,Version),offsetof(G49_TOUCH_RESULT,Trace));return 0;}
