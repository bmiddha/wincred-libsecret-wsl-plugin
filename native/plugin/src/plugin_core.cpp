#include "wincred_plugin/plugin_core.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace
{

constexpr wchar_t kRegistryPrefix[] = L"Software\\wincred-libsecret\\WSLPlugin\\Distributions\\";
constexpr wchar_t kEnabledValueName[] = L"Enabled";

constexpr char kSystemctlPath[] = "/usr/bin/systemctl";
LPCSTR kSystemctlArguments[] = {
    kSystemctlPath,
    "--no-block",
    "start",
    "wincred-libsecret-refresh.service",
    nullptr,
};

class ScopedRegistryKey
{
public:
    ScopedRegistryKey() = default;
    ScopedRegistryKey(const ScopedRegistryKey&) = delete;
    ScopedRegistryKey& operator=(const ScopedRegistryKey&) = delete;

    ~ScopedRegistryKey() noexcept
    {
        if (key_ != nullptr)
        {
            RegCloseKey(key_);
        }
    }

    [[nodiscard]] HKEY* put() noexcept
    {
        return &key_;
    }

    [[nodiscard]] HKEY get() const noexcept
    {
        return key_;
    }

private:
    HKEY key_ = nullptr;
};

class ScopedHandle
{
public:
    ScopedHandle() = default;
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ~ScopedHandle() noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
        {
            static_cast<void>(CloseHandle(handle_));
        }
    }

    [[nodiscard]] HANDLE* put() noexcept
    {
        return &handle_;
    }

    [[nodiscard]] HANDLE get() const noexcept
    {
        return handle_;
    }

private:
    HANDLE handle_ = nullptr;
};

class ScopedImpersonation
{
public:
    explicit ScopedImpersonation(HANDLE token) noexcept
    {
        if (token == nullptr || token == INVALID_HANDLE_VALUE)
        {
            error_ = ERROR_INVALID_HANDLE;
            return;
        }

        if (OpenThreadToken(
                GetCurrentThread(),
                TOKEN_IMPERSONATE,
                TRUE,
                previous_token_.put()) == FALSE)
        {
            error_ = GetLastError();
            if (error_ != ERROR_NO_TOKEN)
            {
                return;
            }
        }

        if (ImpersonateLoggedOnUser(token) != FALSE)
        {
            active_ = true;
            return;
        }

        error_ = GetLastError();
    }

    ScopedImpersonation(const ScopedImpersonation&) = delete;
    ScopedImpersonation& operator=(const ScopedImpersonation&) = delete;

    ~ScopedImpersonation() noexcept
    {
        if (!active_)
        {
            return;
        }

        if (previous_token_.get() != nullptr)
        {
            static_cast<void>(SetThreadToken(nullptr, previous_token_.get()));
        }
        else
        {
            static_cast<void>(RevertToSelf());
        }
    }

    [[nodiscard]] bool active() const noexcept
    {
        return active_;
    }

    [[nodiscard]] HRESULT status() const noexcept
    {
        return error_ == ERROR_SUCCESS ? E_FAIL : HRESULT_FROM_WIN32(error_);
    }

private:
    ScopedHandle previous_token_;
    bool active_ = false;
    DWORD error_ = ERROR_SUCCESS;
};

class ScopedSocket
{
public:
    ScopedSocket() = default;
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;

    ~ScopedSocket() noexcept
    {
        if (socket_ != INVALID_SOCKET)
        {
            static_cast<void>(closesocket(socket_));
        }
    }

    [[nodiscard]] SOCKET* put() noexcept
    {
        return &socket_;
    }

    [[nodiscard]] SOCKET get() const noexcept
    {
        return socket_;
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return socket_ != INVALID_SOCKET;
    }

private:
    SOCKET socket_ = INVALID_SOCKET;
};

[[nodiscard]] HRESULT HResultFromWin32(const LSTATUS status) noexcept
{
    return status == ERROR_SUCCESS ? E_FAIL : HRESULT_FROM_WIN32(static_cast<DWORD>(status));
}

void AppendHex(std::wstring& result, const std::uint64_t value, const std::size_t width)
{
    constexpr wchar_t hex_digits[] = L"0123456789abcdef";

    for (std::size_t index = width; index > 0; --index)
    {
        const auto shift = static_cast<unsigned int>((index - 1U) * 4U);
        const auto nibble = static_cast<std::size_t>((value >> shift) & 0xFU);
        result.push_back(hex_digits[nibble]);
    }
}

[[nodiscard]] bool SupportsWslcHooks(const WSLVersion& version) noexcept
{
    return version.Major > 2U || (version.Major == 2U && version.Minor >= 9U);
}

[[nodiscard]] bool SupportsDistributionRegistrationHooks(const WSLVersion& version) noexcept
{
    return version.Major > 2U ||
        (version.Major == 2U &&
            (version.Minor > 1U || (version.Minor == 1U && version.Revision >= 2U)));
}

void ClearBaseHooks(WSLPluginHooksV1* const hooks) noexcept
{
    hooks->OnVMStarted = nullptr;
    hooks->OnVMStopping = nullptr;
    hooks->OnDistributionStarted = nullptr;
    hooks->OnDistributionStopping = nullptr;
}

void ClearDistributionRegistrationHooks(WSLPluginHooksV1* const hooks) noexcept
{
    hooks->OnDistributionRegistered = nullptr;
    hooks->OnDistributionUnregistered = nullptr;
}

void ClearWslcHooks(WSLPluginHooksV1* const hooks) noexcept
{
    hooks->OnSessionCreated = nullptr;
    hooks->OnSessionStopping = nullptr;
    hooks->ContainerStarted = nullptr;
    hooks->ContainerStopping = nullptr;
    hooks->ImageCreated = nullptr;
    hooks->ImageDeleted = nullptr;
}

} // namespace

namespace wincred::plugin
{

bool IsSupportedWslRuntime(const WSLVersion& version) noexcept
{
    if (version.Major != 2U)
    {
        return version.Major > 2U;
    }

    if (version.Minor != 5U)
    {
        return version.Minor > 5U;
    }

    return version.Revision >= 1U;
}

std::wstring DistributionRegistryPath(const GUID& distribution_id)
{
    std::wstring path(kRegistryPrefix);
    path.reserve(path.size() + 38U);
    path.push_back(L'{');
    AppendHex(path, distribution_id.Data1, 8U);
    path.push_back(L'-');
    AppendHex(path, distribution_id.Data2, 4U);
    path.push_back(L'-');
    AppendHex(path, distribution_id.Data3, 4U);
    path.push_back(L'-');
    AppendHex(path, distribution_id.Data4[0], 2U);
    AppendHex(path, distribution_id.Data4[1], 2U);
    path.push_back(L'-');
    for (std::size_t index = 2U; index < 8U; ++index)
    {
        AppendHex(path, distribution_id.Data4[index], 2U);
    }
    path.push_back(L'}');
    return path;
}

HRESULT ConfigurePluginHooks(
    const WSLPluginAPIV1* const api,
    WSLPluginHooksV1* const hooks,
    const WSLPluginAPI_OnDistributionStarted distribution_started_callback) noexcept
{
    if (hooks == nullptr)
    {
        return E_INVALIDARG;
    }

    ClearBaseHooks(hooks);

    if (api == nullptr)
    {
        return E_INVALIDARG;
    }

    if (SupportsDistributionRegistrationHooks(api->Version))
    {
        ClearDistributionRegistrationHooks(hooks);
    }

    // WSLPluginHooksV1 grew in 2.1.2 and 2.9.0. Older runtimes provide
    // storage only for the hooks available in their API version.
    if (SupportsWslcHooks(api->Version))
    {
        ClearWslcHooks(hooks);
    }

    if (distribution_started_callback == nullptr)
    {
        return E_INVALIDARG;
    }

    if (!IsSupportedWslRuntime(api->Version))
    {
        return WSL_E_PLUGIN_REQUIRES_UPDATE;
    }

    if (api->ExecuteBinaryInDistribution == nullptr)
    {
        return E_NOINTERFACE;
    }

    hooks->OnDistributionStarted = distribution_started_callback;
    return S_OK;
}

HRESULT HandleDistributionStarted(
    const WSLSessionInformation* const session,
    const WSLDistributionInformation* const distribution,
    IEnablementReader& enablement_reader,
    IDistributionCommandLauncher& launcher,
    IDiagnosticSink& diagnostics) noexcept
{
    try
    {
        if (session == nullptr || distribution == nullptr)
        {
            diagnostics.ProviderFailure(DiagnosticOperation::InvalidCallbackArguments, E_INVALIDARG);
            return S_OK;
        }

        const EnablementResult enablement = enablement_reader.Read(session->UserToken, distribution->Id);
        if (FAILED(enablement.status))
        {
            diagnostics.ProviderFailure(DiagnosticOperation::EnablementLookup, enablement.status);
            return S_OK;
        }

        diagnostics.ProviderState(
            DiagnosticOperation::EnablementState,
            enablement.enabled ? S_OK : S_FALSE);
        if (!enablement.enabled)
        {
            return S_OK;
        }

        const HRESULT launch_status = launcher.Start(session->SessionId, distribution->Id);
        diagnostics.ProviderState(DiagnosticOperation::RefreshLaunchResult, launch_status);
        if (FAILED(launch_status))
        {
            diagnostics.ProviderFailure(DiagnosticOperation::RefreshLaunch, launch_status);
        }
    }
    catch (...)
    {
        diagnostics.ProviderFailure(DiagnosticOperation::UnhandledException, E_FAIL);
    }

    return S_OK;
}

EnablementResult RegistryEnablementReader::Read(const HANDLE user_token, const GUID& distribution_id)
{
    const ScopedImpersonation impersonation(user_token);
    if (!impersonation.active())
    {
        return {false, impersonation.status()};
    }

    ScopedRegistryKey current_user;
    LSTATUS status = RegOpenCurrentUser(KEY_QUERY_VALUE, current_user.put());
    if (status != ERROR_SUCCESS)
    {
        return {false, HResultFromWin32(status)};
    }

    ScopedRegistryKey distribution_key;
    const std::wstring path = DistributionRegistryPath(distribution_id);
    status = RegOpenKeyExW(current_user.get(), path.c_str(), 0U, KEY_QUERY_VALUE, distribution_key.put());
    if (status == ERROR_FILE_NOT_FOUND)
    {
        return {false, S_OK};
    }

    if (status != ERROR_SUCCESS)
    {
        return {false, HResultFromWin32(status)};
    }

    DWORD enabled = 0;
    DWORD type = REG_NONE;
    DWORD size = sizeof(enabled);
    status = RegQueryValueExW(
        distribution_key.get(),
        kEnabledValueName,
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(&enabled),
        &size);
    if (status == ERROR_FILE_NOT_FOUND)
    {
        return {false, S_OK};
    }

    if (status != ERROR_SUCCESS)
    {
        return {false, HResultFromWin32(status)};
    }

    if (type != REG_DWORD || size != sizeof(enabled))
    {
        return {false, HRESULT_FROM_WIN32(ERROR_DATATYPE_MISMATCH)};
    }

    return {enabled != 0U, S_OK};
}

SystemdRefreshLauncher::SystemdRefreshLauncher(
    const WSLPluginAPI_ExecuteBinaryInDistribution execute_binary) noexcept :
    execute_binary_(execute_binary)
{
}

HRESULT SystemdRefreshLauncher::Start(const WSLSessionId session_id, const GUID& distribution_id)
{
    if (execute_binary_ == nullptr)
    {
        return E_NOINTERFACE;
    }

    ScopedSocket socket;
    const HRESULT status = execute_binary_(
        session_id,
        &distribution_id,
        kSystemctlPath,
        kSystemctlArguments,
        socket.put());
    if (FAILED(status) || !socket.valid())
    {
        return status;
    }

    // WSL delivers process stdio through this socket. Drain it before closing
    // so the short-lived systemctl process can finish its start request.
    char buffer[256];
    while (::recv(socket.get(), buffer, static_cast<int>(sizeof(buffer)), 0) > 0)
    {
    }
    return S_OK;
}

} // namespace wincred::plugin
