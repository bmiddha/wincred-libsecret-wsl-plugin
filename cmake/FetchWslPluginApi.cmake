include(FetchContent)

set(WSL_PLUGIN_API_VERSION "2.9.3")
set(
    WSL_PLUGIN_API_URL
    "https://api.nuget.org/v3-flatcontainer/microsoft.wsl.pluginapi/${WSL_PLUGIN_API_VERSION}/microsoft.wsl.pluginapi.${WSL_PLUGIN_API_VERSION}.nupkg"
)
set(
    WSL_PLUGIN_API_SHA256
    "95c9e5da4bfaa41b7dfbd81f3077e395b79efc51094cdd32f20d7c140e769c94"
)

FetchContent_Declare(
    wsl_plugin_api
    URL "${WSL_PLUGIN_API_URL}"
    URL_HASH "SHA256=${WSL_PLUGIN_API_SHA256}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(wsl_plugin_api)

set(
    WSL_PLUGIN_API_INCLUDE_DIR
    "${wsl_plugin_api_SOURCE_DIR}/build/native/include"
    CACHE INTERNAL "Microsoft WSL Plugin API include directory"
)
