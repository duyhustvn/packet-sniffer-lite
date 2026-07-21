#ifndef FRAME_H
#define FRAME_H

#include "flow.h"

void process_frame(const uint8_t *buffer, size_t buffer_len, Flow **flows);

#endif