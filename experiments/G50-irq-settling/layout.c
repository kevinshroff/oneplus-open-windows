#include <stdio.h>
#include <stddef.h>
#include "g50_trial.h"
int main(void){
 printf("touch %zu trial %zu touchAt %zu hooksAt %zu\n",sizeof(G50_TOUCH_RESULT),sizeof(G50_TRIAL_RESULT),offsetof(G50_TRIAL_RESULT,Touch),offsetof(G50_TRIAL_RESULT,PoweredHookCalled));
 printf("pins %zu lens %zu cmd %zu waits %zu tx %zu rx %zu version %zu trace %zu\n",offsetof(G50_TOUCH_RESULT,BeforePins),offsetof(G50_TOUCH_RESULT,LengthsBefore),offsetof(G50_TOUCH_RESULT,CommandHistory),offsetof(G50_TOUCH_RESULT,WaitCounts),offsetof(G50_TOUCH_RESULT,Tx),offsetof(G50_TOUCH_RESULT,Rx),offsetof(G50_TOUCH_RESULT,Version),offsetof(G50_TOUCH_RESULT,Trace));printf("settleCount %zu settle %zu sample %zu\n",offsetof(G50_TOUCH_RESULT,SettleCount),offsetof(G50_TOUCH_RESULT,Settle),sizeof(G50_IRQ_SAMPLE));return 0;}
