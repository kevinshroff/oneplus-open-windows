/* SPDX-License-Identifier: MIT */
#ifndef G63_CAPTURE_H
#define G63_CAPTURE_H
#include "g63_protocol.h"
void G63CaptureBegin(G63_REPORT*,uint32_t raw,uint32_t translated,uint32_t bytes);
void G63CaptureRow(G63_REPORT*,int translated,uint32_t index,const void*descriptor);
void G63CaptureEnd(G63_REPORT*);
#endif
