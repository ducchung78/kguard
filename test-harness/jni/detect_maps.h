/*
 * detect_maps.h — /proc/self/maps scanner
 */
#ifndef KGUARD_DETECT_MAPS_H
#define KGUARD_DETECT_MAPS_H

#include "log.h"

void detect_maps_run(detect_score_t *score, int verbose);

#endif
