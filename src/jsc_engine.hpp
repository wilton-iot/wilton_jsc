/* 
 * File:   jsc_engine.hpp
 * Author: alex
 *
 * Created on October 22, 2017, 11:42 PM
 */

#ifndef WILTON_JSC_ENGINE_HPP
#define WILTON_JSC_ENGINE_HPP

#include <string>

#include "staticlib/json.hpp"
#include "staticlib/pimpl.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/script_engine.hpp"

namespace wilton {
namespace jsc {

class jsc_engine : public sl::pimpl::object {
protected:
    /**
     * implementation class
     */
    class impl;
public:
    /**
     * PIMPL-specific constructor
     * 
     * @param pimpl impl object
     */
    PIMPL_CONSTRUCTOR(jsc_engine)

    jsc_engine(sl::io::span<const char> init_code);
    
    support::buffer run_callback_script(sl::io::span<const char> callback_script_json);
};

} // namespace
}

#endif /* WILTON_JSC_ENGINE_HPP */

