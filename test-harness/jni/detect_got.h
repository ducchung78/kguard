/*
 * detect_got.h — GOT/PLT integrity inspector
 */
#ifndef KGUARD_DETECT_GOT_H
#define KGUARD_DETECT_GOT_H

#include "log.h"

void detect_got_run(detect_score_t *score, int verbose);

#endif
