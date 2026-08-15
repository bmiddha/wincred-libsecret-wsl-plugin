cmake_minimum_required(VERSION 3.28)

project(
    wincred-libsecret-wsl-plugin
    VERSION 0.1.0
    DESCRIPTION "WSL Secret Service plugin backed by Windows Credential Manager"
    LANGUAGES CXX
)

if(NOT WIN32)
    message(FATAL_ERROR "The WSL plugin DLL can only be built on Windows.")
endif()

include(CTest)
include(cmake/FetchWslPluginApi.cmake)

add_subdirectory(native/plugin)
