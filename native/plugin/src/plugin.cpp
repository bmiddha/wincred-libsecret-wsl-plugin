#include "wincred_plugin/plugin_core.hpp"

#include <TraceLoggingProvider.h>

#include <atomic>
#include <mutex>

TRACELOGGING_DEFINE_PROVIDER(
    g_trace_provider,
    "WinCredLibsecret.WslPlugin",
    (0x88d50c75, 0x62eb, 0x43e0, 0x9d, 0xac, 0x19, 0x77, 0x45, 0xea, 0x38, 0xe2));

namespace
{

std::once_flag g_trace_provider_registration;
std::atomic<WSLPluginAPI_ExecuteBinaryInDistribution> g_execute_binary_in_distribution = nullptr;

void EnsureTraceProviderRegistered() noexcept
{
    std::call_once(g_trace_provider_registration, []() noexcept {
        static_cast<void>(TraceLoggingRegister(g_trace_provider));
    });
}

class EtwDiagnostics final : public wincred::plugin::IDiagnosticSink
{
public:
    void ProviderFailure(
        const wincred::plugin::DiagnosticOperation operation,
        const HRESULT status) noexcept override
    {
        TraceLoggingWrite(
            g_trace_provider,
            "ProviderFailure",
            TraceLoggingUInt32(static_cast<ULONG>(operation), "Operation"),
            TraceLoggingUInt32(static_cast<ULONG>(status), "Status"));
    }

    void ProviderState(
        const wincred::plugin::DiagnosticOperation operation,
        const HRESULT status) noexcept override
    {
        TraceLoggingWrite(
            g_trace_provider,
            "ProviderState",
            TraceLoggingUInt32(static_cast<ULONG>(operation), "Operation"),
            TraceLoggingUInt32(static_cast<ULONG>(status), "Status"));
    }
};

HRESULT OnDistributionStarted(
    const WSLSessionInformation* const session,
    const WSLDistributionInformation* const distribution) noexcept
{
    EtwDiagnostics diagnostics;
    TraceLoggingWrite(g_trace_provider, "DistributionStarted");

    try
    {
        wincred::plugin::RegistryEnablementReader enablement_reader;
        wincred::plugin::SystemdRefreshLauncher launcher(
            g_execute_binary_in_distribution.load(std::memory_order_acquire));
        return wincred::plugin::HandleDistributionStarted(
            session,
            distribution,
            enablement_reader,
            launcher,
            diagnostics);
    }
    catch (...)
    {
        diagnostics.ProviderFailure(wincred::plugin::DiagnosticOperation::UnhandledException, E_FAIL);
        return S_OK;
    }
}

} // namespace

extern "C" __declspec(dllexport) HRESULT WSLPLUGINAPI_ENTRYPOINTV1(
    const WSLPluginAPIV1* const api,
    WSLPluginHooksV1* const hooks) noexcept
{
    try
    {
        g_execute_binary_in_distribution.store(nullptr, std::memory_order_release);
        EnsureTraceProviderRegistered();

        const HRESULT status = wincred::plugin::ConfigurePluginHooks(api, hooks, &OnDistributionStarted);
        if (FAILED(status))
        {
            EtwDiagnostics diagnostics;
            diagnostics.ProviderFailure(wincred::plugin::DiagnosticOperation::EntryPointRejected, status);
            return status;
        }

        g_execute_binary_in_distribution.store(
            api->ExecuteBinaryInDistribution,
            std::memory_order_release);
        return S_OK;
    }
    catch (...)
    {
        EtwDiagnostics diagnostics;
        diagnostics.ProviderFailure(wincred::plugin::DiagnosticOperation::UnhandledException, E_FAIL);
        return E_FAIL;
    }
}
