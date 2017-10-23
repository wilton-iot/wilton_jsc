/* 
 * File:   jsc_engine.cpp
 * Author: alex
 * 
 * Created on October 22, 2017, 11:42 PM
 */
#include "jsc_engine.hpp"

// todo: removeme
#include <iostream>
// todo: endremoveme

#include <cstring>
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

namespace wilton {
namespace jsc {

namespace { // anonymous

class ctxgroup_deleter {
public:
    void operator()(JSContextGroupRef ctx) {
        if (nullptr != ctx) {
            JSContextGroupRelease(ctx);
        }
    }
};

class ctx_deleter {
public:
    void operator()(JSGlobalContextRef ctx) {
        if (nullptr != ctx) {
            JSGlobalContextRelease(ctx);
        }
    }
};

void register_c_func(JSGlobalContextRef ctx, const std::string& name, JSObjectCallAsFunctionCallback cb) {
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef jname = JSStringCreateWithUTF8CString(name.c_str());
    JSObjectRef fun = JSObjectMakeFunctionWithCallback(ctx, jname, cb);
    JSObjectSetProperty(ctx, global, jname, fun, kJSPropertyAttributeNone, nullptr);
}

std::string from_jstring(JSContextRef ctx, JSValueRef val) {
    //std::cout << JSValueGetType(ctx, val) << std::endl; 
    JSStringRef ref = JSValueToStringCopy(ctx, val, nullptr);
    size_t maxlen = JSStringGetMaximumUTF8CStringSize(ref);
    auto str = std::string();
    str.resize(maxlen);
    size_t len = JSStringGetUTF8CString(ref, std::addressof(str.front()), str.length());
    str.resize(len - 1);
    return str;
}

std::string format_stack_trace(JSContextRef ctx, JSValueRef err) {
    auto stack = from_jstring(ctx, err);
    auto vec = sl::utils::split(stack, '\n');
    auto res = std::string();
    for (size_t i = 0; i < vec.size(); i++) {
        auto& line = vec.at(i);
        if (i > 1) {
            res += "    at ";
        }
        res += line;
        if (i < vec.size() - 1) {
            res += "\n";
        }
    }
    return res;
}

std::string eval_js(JSContextRef ctx, const std::string& code, const std::string& path) {
    //std::cout << code << std::endl;
    //auto ecode = std::string() + "try {" + code + "} catch(e) { print(e.message); }";
    JSStringRef jcode = JSStringCreateWithUTF8CString(code.c_str());
    JSStringRef jpath = JSStringCreateWithUTF8CString(path.c_str());
    JSValueRef err = nullptr;
    auto res = JSEvaluateScript(ctx, jcode, nullptr, jpath, 1, std::addressof(err));
    if (nullptr == res) {
        throw support::exception(TRACEMSG(format_stack_trace(ctx, err)));
    }
    if (JSValueIsString(ctx, res)) {
        return from_jstring(ctx, res);
    }
    return "";
}

std::string string_from_arg(JSContextRef ctx, const JSValueRef arguments[], size_t idx) {
    return from_jstring(ctx, arguments[idx]);
}

JSValueRef print_func(JSContextRef ctx, JSObjectRef function,
        JSObjectRef thiz, size_t args_count, const JSValueRef arguments[],
        JSValueRef* exception) {
    (void) function;
    (void) thiz;
    (void) exception;
    if (args_count > 0) {
        auto val = string_from_arg(ctx, arguments, 0);
        std::cout << val << std::endl;
    } else {
        std::cout << std::endl;
    }
    return JSValueMakeUndefined(ctx);
}

JSValueRef load_func(JSContextRef ctx, JSObjectRef function,
        JSObjectRef thiz, size_t args_count, const JSValueRef arguments[],
        JSValueRef* exception) {
    (void) function;
    (void) thiz;
    (void) exception;
    std::string path = "";
    try {
        if (args_count < 1 || !JSValueIsString(ctx, arguments[0])) {
            throw support::exception(TRACEMSG("Invalid 'load' arguments"));
        }
        auto path = string_from_arg(ctx, arguments, 0);

        // load code
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_script(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        if (0 == code_len) {
            throw support::exception(TRACEMSG(
                    "\nInvalid empty source code loaded, path: [" + path + "]").c_str());
        }
        auto code_str = std::string(code, code_len);
        wilton_free(code);
        eval_js(ctx, code_str.c_str(), path);
        return JSValueMakeUndefined(ctx);
    } catch (const std::exception& e) {
        throw support::exception(TRACEMSG(e.what() + 
                "\nError loading script, path: [" + path + "]").c_str());
    } catch (...) {
        throw support::exception(TRACEMSG(
                "Error loading script, path: [" + path + "]").c_str());
    }    
}

JSValueRef wiltoncall_func(JSContextRef ctx, JSObjectRef function,
        JSObjectRef thiz, size_t args_count, const JSValueRef arguments[],
        JSValueRef* exception) {
    (void) function;
    (void) thiz;
    if (args_count < 2 || !JSValueIsString(ctx, arguments[0]) || !JSValueIsString(ctx, arguments[1])) {
        throw support::exception(TRACEMSG("Invalid 'wiltoncall' arguments"));
    }
    auto name = string_from_arg(ctx, arguments, 0);
    auto input = string_from_arg(ctx, arguments, 1);
    char* out = nullptr;
    int out_len = 0;
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr == err) {
        if (nullptr != out) {
            auto jout = JSStringCreateWithUTF8CString(out);
            wilton_free(out);
            return JSValueMakeString(ctx, jout);
        } else {
            return JSValueMakeUndefined(ctx);
        }
    } else {
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        wilton_free(err);
        auto jmsg = JSStringCreateWithUTF8CString(out);
        JSValueRef val = JSValueMakeString(ctx, jmsg);
        *exception = val;
        return JSValueMakeUndefined(ctx);
    }
}

} // namespace

class jsc_engine::impl : public sl::pimpl::object::impl {
    JSContextGroupRef ctxgroup;
    JSGlobalContextRef ctx;

    
public:
    impl(sl::io::span<const char> init_code) :
    ctxgroup(JSContextGroupCreate()),
    ctx(JSGlobalContextCreateInGroup(ctxgroup, nullptr)) {
        register_c_func(ctx, "print", print_func);
        register_c_func(ctx, "WILTON_load", load_func);
        register_c_func(ctx, "WILTON_wiltoncall", wiltoncall_func);
        auto code_str = std::string(init_code.data(), init_code.size());
        eval_js(ctx, code_str, "wilton-require.js");
    }

    support::buffer run_callback_script(jsc_engine&, sl::io::span<const char> callback_script_json) {
        auto input = std::string(callback_script_json.data(), callback_script_json.size());
        std::replace(input.begin(), input.end(), '\n', ' ');
        auto code = std::string("WILTON_run('" + input + "')");
        auto res = eval_js(ctx, code.c_str(), "CALL");
        return !res.empty() ? support::make_string_buffer(res) : support::make_empty_buffer();
    }    
};

PIMPL_FORWARD_CONSTRUCTOR(jsc_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(jsc_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)

} // namespace
}
