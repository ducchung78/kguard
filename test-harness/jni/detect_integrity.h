/*
 * detect_integrity.h — .text integrity and trampoline scanner
 */
#ifndef KGUARD_DETECT_INTEGRITY_H
#define KGUARD_DETECT_INTEGRITY_H

#include "log.h"

void detect_integrity_run(detect_score_t *score, int verbose);

#endif
