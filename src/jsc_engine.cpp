/*
 * Copyright 2017, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   jsc_engine.cpp
 * Author: alex
 * 
 * Created on October 22, 2017, 11:42 PM
 */
#include "jsc_engine.hpp"

#include <cstdio>
#include <cctype>
#include <functional>
#include <memory>

#include <JavaScriptCore/JavaScript.h>

#include "utf8.h"

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

const std::string st_prefix = "    at ";

std::string jsval_to_string(JSContextRef ctx, JSValueRef val) STATICLIB_NOEXCEPT {
    JSStringRef jstr = JSValueToStringCopy(ctx, val, nullptr);
    if (nullptr == jstr) {
        return "";
    }
    auto deferred = sl::support::defer([jstr]() STATICLIB_NOEXCEPT {
        JSStringRelease(jstr);
    });
    size_t maxlen = JSStringGetMaximumUTF8CStringSize(jstr);
    auto str = std::string();
    str.resize(maxlen);
    size_t len = JSStringGetUTF8CString(jstr, std::addressof(str.front()), str.length());
    if (len > 0) {
        str.resize(len - 1);
    }
    return str;
}

JSStringRef string_to_jsval(const char* str, size_t str_len) {
    auto uvec = std::vector<uint16_t>();
    utf8::utf8to16(str, str + str_len, std::back_inserter(uvec));
    return JSStringCreateWithCharacters(reinterpret_cast<const JSChar*>(uvec.data()), uvec.size());
}

JSStringRef string_to_jsval(const std::string& str) {
    return string_to_jsval(str.data(), str.length());
}

void register_c_func(JSGlobalContextRef ctx, const std::string& name, JSObjectCallAsFunctionCallback cb) {
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef jname = string_to_jsval(name.c_str());
    auto deferred = sl::support::defer([jname]() STATICLIB_NOEXCEPT {
        JSStringRelease(jname);
    });
    JSObjectRef fun = JSObjectMakeFunctionWithCallback(ctx, jname, cb);
    JSObjectSetProperty(ctx, global, jname, fun, kJSPropertyAttributeNone, nullptr);
}

std::string format_stack_trace(JSContextRef ctx, JSValueRef err) STATICLIB_NOEXCEPT {
    auto stack = jsval_to_string(ctx, err);
    auto vec = sl::utils::split(stack, '\n');
    auto res = std::string();
    for (size_t i = 0; i < vec.size(); i++) {
        auto& line = vec.at(i);
        if (line.length() > 1 && !(std::string::npos != line.find("wilton-requirejs/require.js:")) &&
                !(std::string::npos != line.find("wilton-require.js:"))) {
            if (i > 1 && !sl::utils::starts_with(line, st_prefix) &&
                    (line.find('@') != std::string::npos ||
                            (std::string::npos != line.find(".js:") &&
                                    std::isdigit(line.at(line.length() - 1))))) {
                res += st_prefix;
            }
            res += line;
            res.push_back('\n');
        }
    }
    if (res.length() > 0 && '\n' == res.back()) {
        res.pop_back();
    }
    return res;
}

std::string eval_js(JSContextRef ctx, const char* code, size_t code_len, const std::string& path) {
    JSStringRef jcode = string_to_jsval(code, code_len);
    auto deferred_jcode = sl::support::defer([jcode]() STATICLIB_NOEXCEPT {
        JSStringRelease(jcode);
    });
    JSStringRef jpath = string_to_jsval(path);
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
    auto path = std::string();
    try {
        if (args_count < 1 || !JSValueIsString(ctx, arguments[0])) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }
        path = jsval_to_string(ctx, arguments[0]);
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
        eval_js(ctx, code, static_cast<size_t>(code_len), path_short);
        wilton::support::log_debug("wilton.engine.jsc.eval", "Eval complete");
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading script, path: [" + path + "]");
        auto jmsg = string_to_jsval(msg);
        auto deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
            JSStringRelease(jmsg);
        });
        JSValueRef jmsg_ref = JSValueMakeString(ctx, jmsg);
        *exception = JSObjectMakeError(ctx, 1, std::addressof(jmsg_ref), nullptr);
        return JSValueMakeUndefined(ctx);
    } catch (...) {
        auto msg = TRACEMSG("Error(...) loading script, path: [" + path + "]");
        auto jmsg = string_to_jsval(msg);
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
        auto jmsg = string_to_jsval(msg);
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
            "Performing a call, input length: [" + sl::support::to_string(input.length()) + "] ...");
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            auto out_deferred = sl::support::defer([out]() STATICLIB_NOEXCEPT {
                wilton_free(out);
            });
            auto jout = string_to_jsval(out, static_cast<size_t>(out_len));
            auto jout_deferred = sl::support::defer([jout]() STATICLIB_NOEXCEPT {
                JSStringRelease(jout);
            });
            return JSValueMakeString(ctx, jout);
        } else {
            return JSValueMakeNull(ctx);
        }
    } else {
        auto err_deferred = sl::support::defer([err]() STATICLIB_NOEXCEPT {
            wilton_free(err);
        });
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        auto jmsg = string_to_jsval(msg);
        auto jmsg_deferred = sl::support::defer([jmsg]() STATICLIB_NOEXCEPT {
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
        JSGlobalContextRelease(ctx);
        JSContextGroupRelease(ctxgroup);
    }

    impl(sl::io::span<const char> init_code) {
        wilton::support::log_info("wilton.engine.jsc.init", "Initializing engine instance ...");
        this->ctxgroup = JSContextGroupCreate();
        if (nullptr == this->ctxgroup) {
            throw support::exception(TRACEMSG("'JSContextGroupCreate' error"));
        }
        this->ctx = JSGlobalContextCreateInGroup(ctxgroup, nullptr);
        if (nullptr == this->ctx) {
            throw support::exception(TRACEMSG("'JSGlobalContextCreateInGroup' error"));
        }
        register_c_func(ctx, "print", print_func);
        register_c_func(ctx, "WILTON_load", load_func);
        register_c_func(ctx, "WILTON_wiltoncall", wiltoncall_func);
        eval_js(ctx, init_code.data(), init_code.size(), "wilton-require.js");
        wilton::support::log_info("wilton.engine.jsc.init", "Engine initialization complete");
    }

    support::buffer run_callback_script(jsc_engine&, sl::io::span<const char> callback_script_json) {
        wilton::support::log_debug("wilton.engine.jsc.run",
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        // extract wilton_run
        JSStringRef jname = string_to_jsval("WILTON_run");
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
        JSStringRef jcb = string_to_jsval(callback_script_json.data(), callback_script_json.size());
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
        return support::make_null_buffer();
    }

    void run_garbage_collector(jsc_engine&) {
        JSGarbageCollect(ctx);
    }
};

PIMPL_FORWARD_CONSTRUCTOR(jsc_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(jsc_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(jsc_engine, void, run_garbage_collector, (), (), support::exception)

} // namespace
}
