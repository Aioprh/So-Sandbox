// ============================================================================
// demangle.cpp - C++ 符号还原
// ============================================================================
//
// 走 Itanium C++ ABI 的标准实现 __cxa_demangle（libc++abi 提供，随 C++ runtime
// 一起链入），而不是在 Java 里手撸 _Z 编码。手写解析只能处理最简单的情况：
//   _ZN3foo3barEv      → foo::bar
//   _ZN3fooIiEEvT_     → foo<int>      ← 模板参数、cv 限定、重载全都要丢
//   _Z3fooi            → foo(int)      ← 非嵌套格式根本解析不出来
// 这类符号在真实 C++ 库里占绝大多数，所以必须交给 ABI 实现。
#include <jni.h>
#include <cxxabi.h>
#include <cstdlib>
#include <cstring>

extern "C" {

/**
 * 单个符号还原。失败返回 null，由 Java 侧回退到简化解析。
 */
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_demangleSymbol(
        JNIEnv *env, jclass clazz, jstring jMangled) {
    if (!jMangled) return nullptr;

    const char *mangled = env->GetStringUTFChars(jMangled, nullptr);
    if (!mangled) return nullptr;

    int status = -1;
    char *demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
    env->ReleaseStringUTFChars(jMangled, mangled);

    if (status != 0 || !demangled) {
        free(demangled);
        return nullptr;
    }

    jstring result = env->NewStringUTF(demangled);
    free(demangled);
    return result;
}

/**
 * 批量还原。函数表动辄上千条，逐个跨 JNI 开销太大，
 * 这里一次进一次出，内部只做字符串转换。
 */
JNIEXPORT jobjectArray JNICALL
Java_com_example_anative_core_NativeInvoker_demangleBatch(
        JNIEnv *env, jclass clazz, jobjectArray jMangled) {
    if (!jMangled) return nullptr;

    jsize count = env->GetArrayLength(jMangled);
    jclass stringClass = env->FindClass("java/lang/String");

    jobjectArray out = env->NewObjectArray(count, stringClass, nullptr);
    if (!out) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }

    for (jsize i = 0; i < count; i++) {
        jstring item = (jstring) env->GetObjectArrayElement(jMangled, i);
        if (!item) continue;

        const char *mangled = env->GetStringUTFChars(item, nullptr);
        if (mangled) {
            int status = -1;
            char *demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
            env->ReleaseStringUTFChars(item, mangled);

            if (status == 0 && demangled) {
                jstring value = env->NewStringUTF(demangled);
                env->SetObjectArrayElement(out, i, value);
                env->DeleteLocalRef(value);
            }
            free(demangled);
        }
        // 还原失败的位置留 null，Java 侧据此判断是否回退
        env->DeleteLocalRef(item);
    }

    env->DeleteLocalRef(stringClass);
    return out;
}

} // extern "C"
