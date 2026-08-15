#pragma once

#include <winsock2.h>

#include <WslPluginApi.h>

#include <string>

namespace wincred::plugin
{

enum class DiagnosticOperation : unsigned int
{
    InvalidCallbackArguments = 1,
    EnablementLookup = 2,
    RefreshLaunch = 3,
    UnhandledException = 4,
    EntryPointRejected = 5,
    EnablementState = 6,
    RefreshLaunchResult = 7,
};

class IDiagnosticSink
{
public:
    virtual ~IDiagnosticSink() = default;

    virtual void ProviderFailure(DiagnosticOperation operation, HRESULT status) noexcept = 0;
    virtual void ProviderState(DiagnosticOperation operation, HRESULT status) noexcept = 0;
};

struct EnablementResult
{
    bool enabled = false;
    HRESULT status = S_OK;
};

class IEnablementReader
{
public:
    virtual ~IEnablementReader() = default;

    virtual EnablementResult Read(HANDLE user_token, const GUID& distribution_id) = 0;
};

class IDistributionCommandLauncher
{
public:
    virtual ~IDistributionCommandLauncher() = default;

    virtual HRESULT Start(WSLSessionId session_id, const GUID& distribution_id) = 0;
};

[[nodiscard]] bool IsSupportedWslRuntime(const WSLVersion& version) noexcept;
[[nodiscard]] std::wstring DistributionRegistryPath(const GUID& distribution_id);

HRESULT ConfigurePluginHooks(
    const WSLPluginAPIV1* api,
    WSLPluginHooksV1* hooks,
    WSLPluginAPI_OnDistributionStarted distribution_started_callback) noexcept;

HRESULT HandleDistributionStarted(
    const WSLSessionInformation* session,
    const WSLDistributionInformation* distribution,
    IEnablementReader& enablement_reader,
    IDistributionCommandLauncher& launcher,
    IDiagnosticSink& diagnostics) noexcept;

class RegistryEnablementReader final : public IEnablementReader
{
public:
    EnablementResult Read(HANDLE user_token, const GUID& distribution_id) override;
};

class SystemdRefreshLauncher final : public IDistributionCommandLauncher
{
public:
    explicit SystemdRefreshLauncher(WSLPluginAPI_ExecuteBinaryInDistribution execute_binary) noexcept;

    HRESULT Start(WSLSessionId session_id, const GUID& distribution_id) override;

private:
    WSLPluginAPI_ExecuteBinaryInDistribution execute_binary_;
};

} // namespace wincred::plugin
