/*
 * detect_namespace.h — Mount namespace isolation detection
 */
#ifndef KGUARD_DETECT_NAMESPACE_H
#define KGUARD_DETECT_NAMESPACE_H

#include "log.h"

void detect_namespace_run(detect_score_t *score, int verbose);

#endif
