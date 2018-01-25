
cmake_minimum_required ( VERSION 2.8.12 )

# project
project ( wilton_jsc CXX )

# dependencies
set ( ${PROJECT_NAME}_DEPS
        staticlib_config
        staticlib_support
        staticlib_io
        staticlib_utils
        staticlib_json
        staticlib_pimpl )

if ( WILTON_BUILD_FLAVOUR MATCHES "(wheezy)" )
    list ( APPEND ${PROJECT_NAME}_DEPS javascriptcoregtk-3.0 )
elseif ( WILTON_BUILD_FLAVOUR MATCHES "(fedora|xenial|el7)")
    list ( APPEND ${PROJECT_NAME}_DEPS javascriptcoregtk-4.0 )
endif ( )

staticlib_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# library
add_library ( ${PROJECT_NAME} SHARED
        ${CMAKE_CURRENT_LIST_DIR}/src/jsc_engine.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/wiltoncall_jsc.cpp )

target_link_libraries ( ${PROJECT_NAME} PRIVATE
        wilton_core
        wilton_loader
        wilton_logging
        ${${PROJECT_NAME}_DEPS_PC_LIBRARIES} )

if ( STATICLIB_TOOLCHAIN MATCHES "macosx_.+" )
    find_library ( ${PROJECT_NAME}_JSC JavaScriptCore )
    target_link_libraries ( ${PROJECT_NAME} PRIVATE
            ${${PROJECT_NAME}_JSC} )
endif ( )

target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${WILTON_DIR}/core/include
        ${WILTON_DIR}/modules/wilton_loader/include
        ${WILTON_DIR}/modules/wilton_logging/include
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )
        
target_compile_options ( ${PROJECT_NAME} PRIVATE ${${PROJECT_NAME}_DEPS_PC_CFLAGS_OTHER} )

# pkg-config
set ( ${PROJECT_NAME}_PC_CFLAGS "-I${CMAKE_CURRENT_LIST_DIR}/include" )
set ( ${PROJECT_NAME}_PC_LIBS "-L${CMAKE_LIBRARY_OUTPUT_DIRECTORY} -l${PROJECT_NAME}" )
staticlib_list_to_string ( ${PROJECT_NAME}_PC_REQUIRES_PRIVATE "" ${PROJECT_NAME}_DEPS )
configure_file ( ${WILTON_DIR}/resources/buildres/pkg-config.in 
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${PROJECT_NAME}.pc )
