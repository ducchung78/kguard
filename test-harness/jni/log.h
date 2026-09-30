/*
 * log.h — Colored output and score tracking for kguard-detect
 */
#ifndef KGUARD_LOG_H
#define KGUARD_LOG_H

#include <stdio.h>

/* ANSI color codes */
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_BOLD    "\033[1m"

#define LOG_PASS(fmt, ...) \
    printf(CLR_GREEN "[PASS] " CLR_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_FAIL(fmt, ...) \
    printf(CLR_RED "[FAIL] " CLR_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    printf(CLR_YELLOW "[WARN] " CLR_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    printf(CLR_BLUE "[INFO] " CLR_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_DETAIL(fmt, ...) \
    printf(CLR_CYAN "       " CLR_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_HEADER(title) \
    printf("\n" CLR_BOLD "═══════════════════════════════════════════\n" \
           " %s\n" \
           "═══════════════════════════════════════════" CLR_RESET "\n", title)

/* Global score tracking */
typedef struct {
    int total;
    int passed;
    int failed;
    int warnings;
} detect_score_t;

static inline void score_init(detect_score_t *s) {
    s->total = s->passed = s->failed = s->warnings = 0;
}

static inline void score_pass(detect_score_t *s) {
    s->total++;
    s->passed++;
}

static inline void score_fail(detect_score_t *s) {
    s->total++;
    s->failed++;
}

static inline void score_warn(detect_score_t *s) {
    s->total++;
    s->warnings++;
}

static inline void score_print(const detect_score_t *s) {
    printf("\n" CLR_BOLD "═══════════════════════════════════════════\n"
           " DETECTION SUMMARY\n"
           "═══════════════════════════════════════════" CLR_RESET "\n");
    printf(" Total checks:  %d\n", s->total);
    printf(CLR_GREEN  " Passed:        %d" CLR_RESET "\n", s->passed);
    printf(CLR_RED    " Failed:        %d" CLR_RESET "\n", s->failed);
    printf(CLR_YELLOW " Warnings:      %d" CLR_RESET "\n", s->warnings);

    if (s->failed == 0)
        printf(CLR_GREEN "\n ✅ Environment appears CLEAN\n" CLR_RESET);
    else
        printf(CLR_RED "\n 🚨 Tampering indicators detected (%d)\n" CLR_RESET,
               s->failed);
}

#endif /* KGUARD_LOG_H */
