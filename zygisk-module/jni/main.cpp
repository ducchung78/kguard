#include "zygisk.hpp"
#include "cJSON.h"
#include "kguard_client.h"
#include "namespace_cleanup.h"
#include "seccomp_filter.h"
#include "property_spoof.h"

#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <string>
#include <vector>

#define LOG_TAG "KGuard-Zygisk"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define POLICY_PATH "/data/adb/kguard/policy.json"

class KGuardZygisk : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process = nullptr;
        std::string pkg_name;

        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
            if (process) {
                pkg_name = process;
                // Strip process suffix if multi-process (e.g. "com.foo:service" -> "com.foo")
                size_t colon = pkg_name.find(':');
                if (colon != std::string::npos) {
                    pkg_name = pkg_name.substr(0, colon);
                }
            }
        }

        // Fallback: extract package name from app_data_dir (e.g. "/data/user/0/com.foo")
        if (pkg_name.empty() && args->app_data_dir) {
            const char *dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
            if (dir) {
                const char *slash = strrchr(dir, '/');
                if (slash && *(slash + 1) != '\0') {
                    pkg_name = slash + 1;
                }
                env->ReleaseStringUTFChars(args->app_data_dir, dir);
            }
        }

        if (pkg_name.empty()) return;

        uint32_t policy_flags = 0;
        bool is_target = match_policy(pkg_name.c_str(), policy_flags);

        if (is_target) {
            LOGI("Target detected: %s -> applying KGuard policy flags: 0x%x",
                 pkg_name.c_str(), policy_flags);

            // 1. Mount namespace isolation and cleanup
            kguard_isolate_mount_namespace(policy_flags);

            // 2. Seccomp-BPF filter installation (with io_uring defense)
            kguard_install_seccomp_filter(policy_flags);

            // 3. Register PID with Kernel Module
            int kfd = kguard_client_open();
            if (kfd >= 0) {
                kguard_client_register_pid(kfd, getpid(), policy_flags);
                kguard_client_close(kfd);
            }

            // 4. Java-level property sanitization
            kguard_spoof_java_properties(env);
        }

        if (args->nice_name && process) {
            env->ReleaseStringUTFChars(args->nice_name, process);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        (void)args;
        // Zero in-memory footprint: unmap Zygisk module library from memory
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;

    bool match_policy(const char *pkg_name, uint32_t &out_flags) {
        int fd = open(POLICY_PATH, O_RDONLY);
        if (fd < 0) return false;

        char buf[8192];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);

        if (n <= 0) return false;
        buf[n] = '\0';

        cJSON *root = cJSON_Parse(buf);
        if (!root) return false;

        bool matched = false;
        cJSON *profiles = cJSON_GetObjectItemCaseSensitive(root, "profiles");
        if (profiles) {
            cJSON *prof = profiles->child;
            while (prof) {
                cJSON *packages = cJSON_GetObjectItemCaseSensitive(prof, "packages");
                if (packages && packages->type == cJSON_Array) {
                    int size = cJSON_GetArraySize(packages);
                    for (int i = 0; i < size; i++) {
                        cJSON *item = cJSON_GetArrayItem(packages, i);
                        const char *s = cJSON_GetStringValue(item);
                        if (s && strcmp(s, pkg_name) == 0) {
                            matched = true;
                            break;
                        }
                    }
                }
                if (matched) break;
                prof = prof->next;
            }
        }

        if (matched) {
            out_flags = 0xFF; // Default STRICT_ALL
        }

        cJSON_Delete(root);
        return matched;
    }
};

ZYGISK_MODULE_REGISTER(KGuardZygisk)
