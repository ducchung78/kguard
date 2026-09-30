/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ZYGISK_HPP
#define ZYGISK_HPP

#include <jni.h>
#include <stdint.h>

namespace zygisk {

struct Api;
struct AppSpecializeArgs;
struct ServerSpecializeArgs;

enum StateFlag : uint32_t {
    PROCESS_ON_DENYLIST = 1 << 0,
    PROCESS_IS_ROOT = 1 << 1,
};

enum Option : uint32_t {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLCLOSE_MODULE_LIBRARY = 1,
};

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    jboolean *const is_child_zygote = nullptr;
    jboolean *const is_top_app = nullptr;
    jobjectArray *const pkg_data_info_list = nullptr;
    jobjectArray *const whitelisted_data_info_list = nullptr;
    jboolean *const mount_data_dirs = nullptr;
    jboolean *const mount_storage_dirs = nullptr;

    AppSpecializeArgs() = delete;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;

    ServerSpecializeArgs() = delete;
};

struct Api {
    virtual bool connectCompanion() = 0;
    virtual int getModuleDir() = 0;
    virtual void setOption(Option opt) = 0;
    virtual uint32_t getFlags() = 0;
    virtual void hookJniNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *methods, int numMethods) = 0;
    virtual void pltHookRegister(const char *regex, const char *symbol, void *newFunc, void **oldFunc) = 0;
    virtual bool pltHookCommit() = 0;
};

} // namespace zygisk

#define ZYGISK_MODULE_REGISTER(Clazz) \
extern "C" [[gnu::visibility("default")]] void zygisk_module_entry(zygisk::Api *api, JNIEnv *env) { \
    static Clazz module; \
    module.onLoad(api, env); \
}

#endif // ZYGISK_HPP
