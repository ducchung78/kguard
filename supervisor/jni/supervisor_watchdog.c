#include "supervisor_watchdog.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define HEARTBEAT_FILE "/data/adb/kguard/heartbeat"

static void *watchdog_loop(void *arg) {
    (void)arg;
    while (1) {
        FILE *fp = fopen(HEARTBEAT_FILE, "w");
        if (fp) {
            fprintf(fp, "%ld\n", (long)time(NULL));
            fclose(fp);
        }
        sleep(10);
    }
    return NULL;
}

void start_supervisor_watchdog(void) {
    pthread_t th;
    pthread_create(&th, NULL, watchdog_loop, NULL);
    pthread_detach(th);
}
