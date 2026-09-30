/*
 * detect_seccomp.h — Seccomp filter detection
 */
#ifndef KGUARD_DETECT_SECCOMP_H
#define KGUARD_DETECT_SECCOMP_H

#include "log.h"

void detect_seccomp_run(detect_score_t *score, int verbose);

#endif
