#include <stdio.h>
#include <stddef.h>
#include "g42_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G42_TOUCH_RESULT),sizeof(G42_TRIAL_RESULT),offsetof(G42_TRIAL_RESULT,Touch),offsetof(G42_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G42_TOUCH_RESULT,BeforePins),offsetof(G42_TOUCH_RESULT,LengthsBefore),offsetof(G42_TOUCH_RESULT,CommandHistory),offsetof(G42_TOUCH_RESULT,WaitCounts),offsetof(G42_TOUCH_RESULT,Tx),offsetof(G42_TOUCH_RESULT,Rx),offsetof(G42_TOUCH_RESULT,Version),offsetof(G42_TOUCH_RESULT,Trace));return 0;}
