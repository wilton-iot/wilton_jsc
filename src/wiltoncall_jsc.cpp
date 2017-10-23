/* 
 * File:   wiltoncall_jsc.cpp
 * Author: alex
 *
 * Created on October 22, 2017, 11:42 PM
 */
#include <memory>
#include <string>

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"

#include "wilton/wilton.h"
#include "wilton/wilton_loader.h"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"
#include "wilton/support/script_engine.hpp"

#include "jsc_engine.hpp"

namespace wilton {
namespace jsc {

std::shared_ptr<support::script_engine<jsc_engine>> static_engine() {
    static std::shared_ptr<support::script_engine<jsc_engine>> engine = 
            std::make_shared<support::script_engine<jsc_engine>>();
    return engine;
}

support::buffer runscript(sl::io::span<const char> data) {
    auto engine = static_engine();
    return engine->run_script(data);
}

void clean_tls(void*, const char* thread_id, int thread_id_len) {
    auto engine = wilton::jsc::static_engine();
    engine->clean_thread_local(thread_id, thread_id_len);
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        auto err = wilton_register_tls_cleaner(nullptr, wilton::jsc::clean_tls);
        if (nullptr != err) wilton::support::throw_wilton_error(err, TRACEMSG(err));
        wilton::support::register_wiltoncall("runscript_jsc", wilton::jsc::runscript);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}