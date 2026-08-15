if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The WSL plugin must be built for x64.")
endif()

function(configure_wincred_plugin_target target)
    target_compile_features("${target}" PRIVATE cxx_std_23)
    target_include_directories(
        "${target}"
        PRIVATE
            "${WSL_PLUGIN_API_INCLUDE_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )
    target_compile_definitions(
        "${target}"
        PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
    )

    if(MSVC)
        target_compile_options(
            "${target}"
            PRIVATE
                /W4
                /WX
                /permissive-
                /sdl
                /utf-8
        )
    endif()
endfunction()

add_library(wincred_libsecret_wsl_plugin_core STATIC)

target_sources(
    wincred_libsecret_wsl_plugin_core
    PRIVATE
        src/plugin_core.cpp
)

target_include_directories(
    wincred_libsecret_wsl_plugin_core
    PUBLIC
        "${WSL_PLUGIN_API_INCLUDE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
configure_wincred_plugin_target(wincred_libsecret_wsl_plugin_core)
target_link_libraries(wincred_libsecret_wsl_plugin_core PUBLIC Advapi32 Ws2_32)

add_library(wincred_libsecret_wsl_plugin SHARED)
target_sources(wincred_libsecret_wsl_plugin PRIVATE src/plugin.cpp)
configure_wincred_plugin_target(wincred_libsecret_wsl_plugin)
target_link_libraries(wincred_libsecret_wsl_plugin PRIVATE wincred_libsecret_wsl_plugin_core Advapi32)
if(MSVC)
    # Release symbols are packaged for post-mortem diagnostics alongside the
    # signed DLL, without changing the runtime DLL installation location.
    target_compile_options(wincred_libsecret_wsl_plugin PRIVATE $<$<CONFIG:Release>:/Zi>)
    target_link_options(wincred_libsecret_wsl_plugin PRIVATE $<$<CONFIG:Release>:/DEBUG>)
endif()

if(BUILD_TESTING)
    add_executable(wincred_libsecret_wsl_plugin_tests tests/plugin_tests.cpp)
    target_sources(wincred_libsecret_wsl_plugin_tests PRIVATE src/plugin.cpp)
    configure_wincred_plugin_target(wincred_libsecret_wsl_plugin_tests)
    target_link_libraries(
        wincred_libsecret_wsl_plugin_tests
        PRIVATE
            wincred_libsecret_wsl_plugin_core
    )
    add_test(NAME wincred_libsecret_wsl_plugin_tests COMMAND wincred_libsecret_wsl_plugin_tests)
endif()

set_target_properties(
    wincred_libsecret_wsl_plugin
    PROPERTIES
        OUTPUT_NAME "wincred-libsecret-wsl-plugin"
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/artifacts/$<CONFIG>/windows"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/artifacts/$<CONFIG>/windows"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/artifacts/$<CONFIG>/windows"
        PDB_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/artifacts/$<CONFIG>/symbols"
)
