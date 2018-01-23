/* 
 * File:   jsc_engine.cpp
 * Author: alex
 * 
 * Created on October 22, 2017, 11:42 PM
 */
#include "jsc_engine.hpp"

#include <cstdio>
#include <functional>
#include <memory>

#include <JavaScriptCore/JSContextRef.h>
#include <JavaScriptCore/JSStringRef.h>

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wiltoncall.h"
#include "wilton/wilton_loader.h"

#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

namespace wilton {
namespace jsc {

namespace { // anonymous

void register_c_func(JSGlobalContextRef ctx, const std::string& name, JSObjectCallAsFunctionCallback cb) {
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef jname = JSStringCreateWithUTF8CString(name.c_str());
    auto deferred = sl::support::defer([jname]() STATICLIB_NOEXCEPT {
        JSStringRelease(jname);
    });
    JSObjectRef fun = JSObjectMakeFunctionWithCallback(ctx, jname, cb);
    JSObjectSetProperty(ctx, global, jname, fun, kJSPropertyAttributeNone, nullptr);
}

std::string jsval_to_string(JSContextRef ctx, JSValueRef val) STATICLIB_NOEXCEPT {
    JSStringRef jstr = JSValueToStringCopy(ctx, val, nullptr);
    if (nullptr ==jstr) {
        return "";
    }
    auto deferred = sl::support::defer([jstr]() STATICLIB_NOEXCEPT {
        JSStringRelease(jstr);
    });
    size_t maxlen = JSStringGetMaximumUTF8CStringSize(jstr);
    auto str = std::string();
    str.resize(maxlen);
    size_t len = JSStringGetUTF8CString(jstr, std::addressof(str.front()), str.length());
    if(len > 0) {
        str.resize(len - 1);
    }
    return str;
}

std::string format_stack_trace(JSContextRef ctx, JSValueRef err) STATICLIB_NOEXCEPT {
    static std::string prefix = "    at ";
    auto stack = jsval_to_string(ctx, err);
    auto vec = sl::utils::split(stack, '\n');
    auto res = std::string();
    for (size_t i = 0; i < vec.size(); i++) {
        auto& line = vec.at(i);
        if(line.length() > 1 && !(std::string::npos != line.find("@/wilton-requirejs/require.js:")) &&
                !(std::string::npos != line.find("@wilton-require.js:"))) {
            if (i > 1 && !sl::utils::starts_with(line, prefix) && 
                    (line.find('@') != std::string::npos || '/' == line.front() || ':' == line.at(1))) {
                res += prefix;
            }
            res += line;
            if (i < vec.size() - 1) {
                res += "\n";
            }
        }
    }
    return res;
}

std::string eval_js(JSContextRef ctx, const char* code, const std::string& path) {
    JSStringRef jcode = JSStringCreateWithUTF8CString(code);
    auto deferred_jcode = sl::support::defer([jcode]() STATICLIB_NOEXCEPT {
        JSStringRelease(jcode);
    });
    JSStringRef jpath = JSStringCreateWithUTF8CString(path.c_str());
    auto deferred_jpath = sl::support::defer([jpath]() STATICLIB_NOEXCEPT {
        JSStringRelease(jpath);
    });
    JSValueRef err = nullptr;
    auto res = JSEvaluateScript(ctx, jcode, nullptr, jpath, 1, std::addressof(err));
    if (nullptr == res) {
        throw support::exception(TRACEMSG(format_stack_trace(ctx, err)));
    }
    if (JSValueIsString(ctx, res)) {
        return jsval_to_string(ctx, res);
    }
    return "";
}

JSValueRef print_func(JSContextRef ctx, JSObjectRef /* function */,
        JSObjectRef /* thiz */, size_t args_count, const JSValueRef arguments[],
        JSValueRef* /* exception */) STATICLIB_NOEXCEPT {
    if (args_count > 0) {
        auto val = jsval_to_string(ctx, arguments[0]);
        puts(val.c_str());
    } else {
        puts("");
    }
    return JSValueMakeUndefined(ctx);
}

JSValueRef load_func(JSContextRef ctx, JSObjectRef /* function */,
        JSObjectRef /* thiz */, size_t args_count, const JSValueRef arguments[],
        JSValueRef* exception) STATICLIB_NOEXCEPT {
    std::string path = "";
    try {
        if (args_count < 1 || !JSValueIsString(ctx, arguments[0])) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }
        auto path = jsval_to_string(ctx, arguments[0]);
        // load code
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        auto deferred = sl::support::defer([code] () STATICLIB_NOEXCEPT {
            wilton_free(code);
        });
        auto path_short = support::script_engine_map_detail::shorten_script_path(path);
        wilton::support::log_debug("wilton.engine.jsc.eval",
                "Evaluating source file, path: [" + path + "] ...");
        eval_js(ctx, code, path_short);
        wilton::support::log_debug("wilton.engine.jsc.eval", "Eval complete");
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading script, path: [" + path + "]");
        auto jmsg = JSStringCreateWithUTF8CString(msg.c_str());
        auto deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
            JSStringRelease(jmsg);
        });
        JSValueRef jmsg_ref = JSValueMakeString(ctx, jmsg);
        *exception = JSObjectMakeError(ctx, 1, std::addressof(jmsg_ref), nullptr);
        return JSValueMakeUndefined(ctx);
    } catch (...) {
        auto msg = TRACEMSG("Error loading script, path: [" + path + "]");
        auto jmsg = JSStringCreateWithUTF8CString(msg.c_str());
        auto deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
            JSStringRelease(jmsg);
        });
        JSValueRef jmsg_ref = JSValueMakeString(ctx, jmsg);
        *exception = JSObjectMakeError(ctx, 1, std::addressof(jmsg_ref), nullptr);
        return JSValueMakeUndefined(ctx);
    }
    return JSValueMakeUndefined(ctx);
}

JSValueRef wiltoncall_func(JSContextRef ctx, JSObjectRef /* function */,
        JSObjectRef /* thiz */, size_t args_count, const JSValueRef arguments[],
        JSValueRef* exception) STATICLIB_NOEXCEPT {
    if (args_count < 2 || !JSValueIsString(ctx, arguments[0]) || !JSValueIsString(ctx, arguments[1])) {
        auto msg = TRACEMSG("Invalid arguments specified");
        auto jmsg = JSStringCreateWithUTF8CString(msg.c_str());
        auto deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
            JSStringRelease(jmsg);
        });
        JSValueRef jmsg_ref = JSValueMakeString(ctx, jmsg);
        *exception = JSObjectMakeError(ctx, 1, std::addressof(jmsg_ref), nullptr);
        return JSValueMakeUndefined(ctx);
    }
    auto name = jsval_to_string(ctx, arguments[0]);
    auto input = jsval_to_string(ctx, arguments[1]);
    char* out = nullptr;
    int out_len = 0;
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Performing a call,  input length: [" + sl::support::to_string(input.length()) + "] ...");
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            auto jout = JSStringCreateWithUTF8CString(out);
            auto deferred = sl::support::defer([jout]() STATICLIB_NOEXCEPT {
                JSStringRelease(jout);
            });
            wilton_free(out);
            return JSValueMakeString(ctx, jout);
        } else {
            return JSValueMakeNull(ctx);
        }
    } else {
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        wilton_free(err);
        auto jmsg = JSStringCreateWithUTF8CString(msg.c_str());
        auto deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
            JSStringRelease(jmsg);
        });
        JSValueRef jmsg_ref = JSValueMakeString(ctx, jmsg);
        *exception = JSObjectMakeError(ctx, 1, std::addressof(jmsg_ref), nullptr);
        return JSValueMakeUndefined(ctx);
    }
}

} // namespace

class jsc_engine::impl : public sl::pimpl::object::impl {
    JSContextGroupRef ctxgroup = nullptr;
    JSGlobalContextRef ctx = nullptr;

public:
    ~impl() STATICLIB_NOEXCEPT {
        if (nullptr != ctx) {
            JSGlobalContextRelease(ctx);
        }
        if (nullptr != ctxgroup) {
            JSContextGroupRelease(ctxgroup);
        }
    }
    
    impl(sl::io::span<const char> init_code) {
        wilton::support::log_info("wilton.engine.jsc.init", "Initializing engine instance ...");
        this->ctxgroup = JSContextGroupCreate();
        this->ctx = JSGlobalContextCreateInGroup(ctxgroup, nullptr);
        register_c_func(ctx, "print", print_func);
        register_c_func(ctx, "WILTON_load", load_func);
        register_c_func(ctx, "WILTON_wiltoncall", wiltoncall_func);
        eval_js(ctx, init_code.data(), "wilton-require.js");
        wilton::support::log_info("wilton.engine.jsc.init", "Engine initialization complete");
    }

    support::buffer run_callback_script(jsc_engine&, sl::io::span<const char> callback_script_json) {
        wilton::support::log_debug("wilton.engine.jsc.run",
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        // extract wilton_run
        JSStringRef jname = JSStringCreateWithUTF8CString("WILTON_run");
        auto deferred_name = sl::support::defer([jname]() STATICLIB_NOEXCEPT {
            JSStringRelease(jname);
        });
        JSObjectRef global = JSContextGetGlobalObject(ctx);
        JSValueRef ref = JSObjectGetProperty(ctx, global, jname, nullptr);
        if (!JSValueIsObject(ctx, ref)) {
            throw support::exception(TRACEMSG("Error accessing 'WILTON_run' function: not an object"));
        }
        JSObjectRef wilton_run = JSValueToObject(ctx, ref, nullptr);
        if (nullptr == wilton_run) {
            throw support::exception(TRACEMSG("Error accessing 'WILTON_run' function: null"));
        }
        if (!JSObjectIsFunction(ctx, wilton_run)) {
            throw support::exception(TRACEMSG("Error accessing 'WILTON_run' function: not a function"));
        }
        // call
        JSStringRef jcb = JSStringCreateWithUTF8CString(callback_script_json.data());
        auto deferred_cb = sl::support::defer([jcb]() STATICLIB_NOEXCEPT {
            JSStringRelease(jcb);
        });
        JSValueRef jcb_val = JSValueMakeString(ctx, jcb);
        JSValueRef err = nullptr;
        JSValueRef res = JSObjectCallAsFunction(ctx, wilton_run, nullptr, 1, std::addressof(jcb_val), std::addressof(err));
        wilton::support::log_debug("wilton.engine.jsc.run",
                "Callback run complete, result: [" + sl::support::to_string_bool(nullptr != res) + "]");
        if (nullptr == res) {
            throw support::exception(TRACEMSG(format_stack_trace(ctx, err)));
        }
        if (JSValueIsString(ctx, res)) {
            auto str = jsval_to_string(ctx, res);
            return support::make_string_buffer(str);
        }
        return support::make_empty_buffer();
    }
};

PIMPL_FORWARD_CONSTRUCTOR(jsc_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(jsc_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)

} // namespace
}
