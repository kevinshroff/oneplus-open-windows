#pragma once
#include <ntifs.h>
#include "local_bank_native.h"
/* Returned only by actual MMU1 EnterNs. Grant is a projection of its validated
 * translated START descriptor, never a caller physical-address assertion. */
typedef struct {ULONGLONG Token,ProviderGeneration;CM_RESOURCE_LIST Grant;}OPEN_NS_SCOPE;
