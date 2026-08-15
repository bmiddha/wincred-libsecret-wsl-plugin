#include "wincred_plugin/plugin_core.hpp"

#include <cstdio>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

extern "C" HRESULT WSLPLUGINAPI_ENTRYPOINTV1(
    const WSLPluginAPIV1* api,
    WSLPluginHooksV1* hooks) noexcept;

namespace
{

int g_failures = 0;

void Check(const bool condition, const char* const expression, const char* const test_name)
{
    if (!condition)
    {
        std::printf("FAILED %s: %s\n", test_name, expression);
        ++g_failures;
    }
}

#define CHECK(test_name, expression) Check((expression), #expression, test_name)

GUID TestGuid() noexcept
{
    return {
        0x01234567,
        0x89AB,
        0xCDEF,
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
    };
}

bool SameGuid(const GUID& left, const GUID& right) noexcept
{
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

HRESULT TestDistributionStarted(
    const WSLSessionInformation*,
    const WSLDistributionInformation*) noexcept
{
    return S_OK;
}

HRESULT TestDistributionRegistered(
    const WSLSessionInformation*,
    const WslOfflineDistributionInformation*) noexcept
{
    return S_OK;
}

HRESULT TestDistributionUnregistered(
    const WSLSessionInformation*,
    const WslOfflineDistributionInformation*) noexcept
{
    return S_OK;
}

HRESULT TestSessionCreated(const WSLCSessionInformation*) noexcept
{
    return S_OK;
}

HRESULT TestSessionStopping(const WSLCSessionInformation*) noexcept
{
    return S_OK;
}

HRESULT TestContainerStarted(const WSLCSessionInformation*, LPCSTR) noexcept
{
    return S_OK;
}

HRESULT TestContainerStopping(const WSLCSessionInformation*, LPCSTR) noexcept
{
    return S_OK;
}

HRESULT TestImageCreated(const WSLCSessionInformation*, LPCSTR) noexcept
{
    return S_OK;
}

HRESULT TestImageDeleted(const WSLCSessionInformation*, LPCSTR) noexcept
{
    return S_OK;
}

struct ExecuteCapture
{
    bool called = false;
    WSLSessionId session_id = 0;
    GUID distribution_id = {};
    const char* path = nullptr;
    LPCSTR* arguments = nullptr;
    SOCKET returned_socket = INVALID_SOCKET;
    bool return_socket = false;
};

ExecuteCapture g_execute_capture;

HRESULT CaptureExecuteBinaryInDistribution(
    const WSLSessionId session_id,
    const GUID* const distribution_id,
    const LPCSTR path,
    LPCSTR* const arguments,
    SOCKET* const socket)
{
    g_execute_capture.called = true;
    g_execute_capture.session_id = session_id;
    if (distribution_id != nullptr)
    {
        g_execute_capture.distribution_id = *distribution_id;
    }
    g_execute_capture.path = path;
    g_execute_capture.arguments = arguments;
    if (g_execute_capture.return_socket)
    {
        *socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        u_long nonblocking = 1;
        if (*socket == INVALID_SOCKET ||
            ioctlsocket(*socket, FIONBIO, &nonblocking) == SOCKET_ERROR)
        {
            if (*socket != INVALID_SOCKET)
            {
                closesocket(*socket);
            }
            *socket = INVALID_SOCKET;
            return E_FAIL;
        }
        g_execute_capture.returned_socket = *socket;
    }
    else
    {
        *socket = INVALID_SOCKET;
    }
    return S_OK;
}

class FakeEnablementReader final : public wincred::plugin::IEnablementReader
{
public:
    wincred::plugin::EnablementResult result = {};
    int calls = 0;
    HANDLE observed_token = nullptr;
    GUID observed_distribution = {};

    wincred::plugin::EnablementResult Read(
        const HANDLE user_token,
        const GUID& distribution_id) override
    {
        ++calls;
        observed_token = user_token;
        observed_distribution = distribution_id;
        return result;
    }
};

class FakeLauncher final : public wincred::plugin::IDistributionCommandLauncher
{
public:
    HRESULT result = S_OK;
    int calls = 0;
    WSLSessionId observed_session_id = 0;
    GUID observed_distribution = {};

    HRESULT Start(const WSLSessionId session_id, const GUID& distribution_id) override
    {
        ++calls;
        observed_session_id = session_id;
        observed_distribution = distribution_id;
        return result;
    }
};

class FakeDiagnostics final : public wincred::plugin::IDiagnosticSink
{
public:
    int calls = 0;
    int state_calls = 0;
    wincred::plugin::DiagnosticOperation operation =
        wincred::plugin::DiagnosticOperation::InvalidCallbackArguments;
    HRESULT status = S_OK;
    wincred::plugin::DiagnosticOperation state_operation =
        wincred::plugin::DiagnosticOperation::InvalidCallbackArguments;
    HRESULT state_status = S_OK;

    void ProviderFailure(
        const wincred::plugin::DiagnosticOperation reported_operation,
        const HRESULT reported_status) noexcept override
    {
        ++calls;
        operation = reported_operation;
        status = reported_status;
    }

    void ProviderState(
        const wincred::plugin::DiagnosticOperation reported_operation,
        const HRESULT reported_status) noexcept override
    {
        ++state_calls;
        state_operation = reported_operation;
        state_status = reported_status;
    }
};

class ThrowingEnablementReader final : public wincred::plugin::IEnablementReader
{
public:
    wincred::plugin::EnablementResult Read(HANDLE, const GUID&) override
    {
        throw 1;
    }
};

WSLSessionInformation TestSession() noexcept
{
    WSLSessionInformation session = {};
    session.SessionId = 42;
    session.UserToken = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(1));
    return session;
}

WSLDistributionInformation TestDistribution() noexcept
{
    WSLDistributionInformation distribution = {};
    distribution.Id = TestGuid();
    return distribution;
}

// Covers ConfigurePluginHooks across the WSLPluginHooksV1 layouts the plugin
// has to tolerate, plus the argument validation failures. Every phase asserts
// that hooks absent from the runtime's layout are left untouched, because
// writing past the runtime's allocation would corrupt WSL's memory.
void TestVersionGatingAndHookRegistration()
{
    constexpr char test_name[] = "version gating and hook registration";
    WSLPluginAPIV1 api = {};
    api.ExecuteBinaryInDistribution = &CaptureExecuteBinaryInDistribution;

    // 2.0.0 is unsupported and its layout has none of the later hooks, so the
    // request is rejected and the caller-provided hooks stay as they were.
    WSLPluginHooksV1 hooks = {};
    api.Version = {2, 0, 0};
    hooks.OnDistributionRegistered = &TestDistributionRegistered;
    hooks.OnDistributionUnregistered = &TestDistributionUnregistered;
    hooks.OnSessionCreated = &TestSessionCreated;
    hooks.OnSessionStopping = &TestSessionStopping;
    hooks.ContainerStarted = &TestContainerStarted;
    hooks.ContainerStopping = &TestContainerStopping;
    hooks.ImageCreated = &TestImageCreated;
    hooks.ImageDeleted = &TestImageDeleted;
    CHECK(
        test_name,
        wincred::plugin::ConfigurePluginHooks(&api, &hooks, &TestDistributionStarted) ==
            WSL_E_PLUGIN_REQUIRES_UPDATE);
    CHECK(test_name, hooks.OnDistributionStarted == nullptr);
    CHECK(test_name, hooks.OnDistributionRegistered == &TestDistributionRegistered);
    CHECK(test_name, hooks.OnDistributionUnregistered == &TestDistributionUnregistered);
    CHECK(test_name, hooks.OnSessionCreated == &TestSessionCreated);
    CHECK(test_name, hooks.OnSessionStopping == &TestSessionStopping);
    CHECK(test_name, hooks.ContainerStarted == &TestContainerStarted);
    CHECK(test_name, hooks.ContainerStopping == &TestContainerStopping);
    CHECK(test_name, hooks.ImageCreated == &TestImageCreated);
    CHECK(test_name, hooks.ImageDeleted == &TestImageDeleted);

    // 2.7.11 is supported and includes the registration hooks, but not the WSLc
    // hooks added in 2.9.0, so only the former may be cleared.
    api.Version = {2, 7, 11};
    hooks = {};
    hooks.OnDistributionRegistered = &TestDistributionRegistered;
    hooks.OnDistributionUnregistered = &TestDistributionUnregistered;
    hooks.OnSessionCreated = &TestSessionCreated;
    hooks.OnSessionStopping = &TestSessionStopping;
    hooks.ContainerStarted = &TestContainerStarted;
    hooks.ContainerStopping = &TestContainerStopping;
    hooks.ImageCreated = &TestImageCreated;
    hooks.ImageDeleted = &TestImageDeleted;
    const HRESULT configured = wincred::plugin::ConfigurePluginHooks(
        &api,
        &hooks,
        &TestDistributionStarted);

    CHECK(test_name, configured == S_OK);
    CHECK(test_name, hooks.OnDistributionStarted == &TestDistributionStarted);
    CHECK(test_name, hooks.OnVMStarted == nullptr);
    CHECK(test_name, hooks.OnVMStopping == nullptr);
    CHECK(test_name, hooks.OnDistributionStopping == nullptr);
    CHECK(test_name, hooks.OnDistributionRegistered == nullptr);
    CHECK(test_name, hooks.OnDistributionUnregistered == nullptr);
    CHECK(test_name, hooks.OnSessionCreated == &TestSessionCreated);
    CHECK(test_name, hooks.OnSessionStopping == &TestSessionStopping);
    CHECK(test_name, hooks.ContainerStarted == &TestContainerStarted);
    CHECK(test_name, hooks.ContainerStopping == &TestContainerStopping);
    CHECK(test_name, hooks.ImageCreated == &TestImageCreated);
    CHECK(test_name, hooks.ImageDeleted == &TestImageDeleted);

    // 2.9.0 grew the struct, so the WSLc hooks are now in range and are cleared
    // as well.
    api.Version = {2, 9, 0};
    CHECK(
        test_name,
        wincred::plugin::ConfigurePluginHooks(&api, &hooks, &TestDistributionStarted) == S_OK);
    CHECK(test_name, hooks.OnSessionCreated == nullptr);
    CHECK(test_name, hooks.OnSessionStopping == nullptr);
    CHECK(test_name, hooks.ContainerStarted == nullptr);
    CHECK(test_name, hooks.ContainerStopping == nullptr);
    CHECK(test_name, hooks.ImageCreated == nullptr);
    CHECK(test_name, hooks.ImageDeleted == nullptr);

    // 2.5.0 is below the supported floor, so registration must be rejected
    // without leaving a dangling hook behind.
    api.Version = {2, 5, 0};
    hooks.OnDistributionStarted = &TestDistributionStarted;
    const HRESULT rejected = wincred::plugin::ConfigurePluginHooks(
        &api,
        &hooks,
        &TestDistributionStarted);

    CHECK(test_name, rejected == WSL_E_PLUGIN_REQUIRES_UPDATE);
    CHECK(test_name, hooks.OnDistributionStarted == nullptr);
    CHECK(test_name, !wincred::plugin::IsSupportedWslRuntime({2, 4, 99}));
    CHECK(test_name, wincred::plugin::IsSupportedWslRuntime({2, 5, 1}));
    CHECK(test_name, wincred::plugin::IsSupportedWslRuntime({3, 0, 0}));
    CHECK(test_name, wincred::plugin::IsSupportedWslRuntime({2, 6, 0}));
    CHECK(test_name, !wincred::plugin::IsSupportedWslRuntime({1, 99, 99}));

    // Missing arguments and a missing ExecuteBinaryInDistribution entry point
    // are configuration errors rather than version failures.
    hooks.OnDistributionStarted = &TestDistributionStarted;
    CHECK(
        test_name,
        wincred::plugin::ConfigurePluginHooks(nullptr, &hooks, &TestDistributionStarted) ==
            E_INVALIDARG);
    CHECK(test_name, hooks.OnDistributionStarted == nullptr);
    CHECK(
        test_name,
        wincred::plugin::ConfigurePluginHooks(&api, nullptr, &TestDistributionStarted) ==
            E_INVALIDARG);
    api.Version = {2, 5, 1};
    api.ExecuteBinaryInDistribution = nullptr;
    CHECK(
        test_name,
        wincred::plugin::ConfigurePluginHooks(&api, &hooks, &TestDistributionStarted) ==
            E_NOINTERFACE);
}

void TestRegistryPath()
{
    constexpr char test_name[] = "registry path";
    const std::wstring expected =
        L"Software\\wincred-libsecret\\WSLPlugin\\Distributions\\{01234567-89ab-cdef-0123-456789abcdef}";

    CHECK(test_name, wincred::plugin::DistributionRegistryPath(TestGuid()) == expected);
}

void TestNonfatalEnablementAndLaunchFailures()
{
    constexpr char test_name[] = "nonfatal failures";
    FakeEnablementReader reader;
    FakeLauncher launcher;
    FakeDiagnostics diagnostics;
    const WSLSessionInformation session = TestSession();
    const WSLDistributionInformation distribution = TestDistribution();

    reader.result = {false, S_OK};
    CHECK(
        test_name,
        wincred::plugin::HandleDistributionStarted(
            &session,
            &distribution,
            reader,
            launcher,
            diagnostics) == S_OK);
    CHECK(test_name, reader.calls == 1);
    CHECK(test_name, launcher.calls == 0);
    CHECK(test_name, diagnostics.calls == 0);
    CHECK(test_name, diagnostics.state_calls == 1);
    CHECK(test_name, diagnostics.state_operation == wincred::plugin::DiagnosticOperation::EnablementState);
    CHECK(test_name, diagnostics.state_status == S_FALSE);

    reader.result = {false, E_ACCESSDENIED};
    CHECK(
        test_name,
        wincred::plugin::HandleDistributionStarted(
            &session,
            &distribution,
            reader,
            launcher,
            diagnostics) == S_OK);
    CHECK(test_name, launcher.calls == 0);
    CHECK(test_name, diagnostics.calls == 1);
    CHECK(test_name, diagnostics.operation == wincred::plugin::DiagnosticOperation::EnablementLookup);
    CHECK(test_name, diagnostics.status == E_ACCESSDENIED);

    reader.result = {true, S_OK};
    launcher.result = E_FAIL;
    CHECK(
        test_name,
        wincred::plugin::HandleDistributionStarted(
            &session,
            &distribution,
            reader,
            launcher,
            diagnostics) == S_OK);
    CHECK(test_name, launcher.calls == 1);
    CHECK(test_name, launcher.observed_session_id == session.SessionId);
    CHECK(test_name, SameGuid(launcher.observed_distribution, distribution.Id));
    CHECK(test_name, diagnostics.calls == 2);
    CHECK(test_name, diagnostics.operation == wincred::plugin::DiagnosticOperation::RefreshLaunch);
    CHECK(test_name, diagnostics.status == E_FAIL);
    CHECK(test_name, diagnostics.state_calls == 3);
    CHECK(test_name, diagnostics.state_operation == wincred::plugin::DiagnosticOperation::RefreshLaunchResult);
    CHECK(test_name, diagnostics.state_status == E_FAIL);

    CHECK(
        test_name,
        wincred::plugin::HandleDistributionStarted(
            nullptr,
            &distribution,
            reader,
            launcher,
            diagnostics) == S_OK);
    CHECK(test_name, diagnostics.operation == wincred::plugin::DiagnosticOperation::InvalidCallbackArguments);

    ThrowingEnablementReader throwing_reader;
    CHECK(
        test_name,
        wincred::plugin::HandleDistributionStarted(
            &session,
            &distribution,
            throwing_reader,
            launcher,
            diagnostics) == S_OK);
    CHECK(test_name, diagnostics.operation == wincred::plugin::DiagnosticOperation::UnhandledException);
}

void TestRefreshLaunchArguments()
{
    constexpr char test_name[] = "refresh launch arguments";
    g_execute_capture = {};
    wincred::plugin::SystemdRefreshLauncher launcher(&CaptureExecuteBinaryInDistribution);
    const GUID distribution_id = TestGuid();

    CHECK(test_name, launcher.Start(77, distribution_id) == S_OK);
    CHECK(test_name, g_execute_capture.called);
    CHECK(test_name, g_execute_capture.session_id == 77);
    CHECK(test_name, SameGuid(g_execute_capture.distribution_id, distribution_id));
    CHECK(test_name, std::strcmp(g_execute_capture.path, "/usr/bin/systemctl") == 0);
    CHECK(test_name, std::strcmp(g_execute_capture.arguments[0], "/usr/bin/systemctl") == 0);
    CHECK(test_name, std::strcmp(g_execute_capture.arguments[1], "--no-block") == 0);
    CHECK(test_name, std::strcmp(g_execute_capture.arguments[2], "start") == 0);
    CHECK(
        test_name,
        std::strcmp(g_execute_capture.arguments[3], "wincred-libsecret-refresh.service") == 0);
    CHECK(test_name, g_execute_capture.arguments[4] == nullptr);
    CHECK(
        test_name,
        wincred::plugin::SystemdRefreshLauncher(nullptr).Start(77, distribution_id) ==
            E_NOINTERFACE);
}

void TestSocketOwnershipAndRepeatedCallbacks()
{
    constexpr char test_name[] = "socket ownership and repeated callbacks";
    WSADATA data = {};
    CHECK(test_name, WSAStartup(MAKEWORD(2, 2), &data) == 0);

    g_execute_capture = {};
    g_execute_capture.return_socket = true;
    wincred::plugin::SystemdRefreshLauncher launcher(&CaptureExecuteBinaryInDistribution);
    CHECK(test_name, launcher.Start(1, TestGuid()) == S_OK);
    int socket_type = 0;
    int socket_type_size = sizeof(socket_type);
    CHECK(
        test_name,
        getsockopt(
            g_execute_capture.returned_socket,
            SOL_SOCKET,
            SO_TYPE,
            reinterpret_cast<char*>(&socket_type),
            &socket_type_size) == SOCKET_ERROR);
    CHECK(test_name, WSAGetLastError() == WSAENOTSOCK);
    WSACleanup();

    std::atomic<int> completed = 0;
    std::vector<std::thread> workers;
    for (int index = 0; index < 24; ++index)
    {
        workers.emplace_back([&completed]() {
            FakeEnablementReader reader;
            reader.result = {true, S_OK};
            FakeLauncher callback_launcher;
            FakeDiagnostics diagnostics;
            const WSLSessionInformation session = TestSession();
            const WSLDistributionInformation distribution = TestDistribution();
            if (wincred::plugin::HandleDistributionStarted(
                    &session,
                    &distribution,
                    reader,
                    callback_launcher,
                    diagnostics) == S_OK &&
                callback_launcher.calls == 1 &&
                diagnostics.calls == 0)
            {
                ++completed;
            }
        });
    }
    for (std::thread& worker : workers)
    {
        worker.join();
    }
    CHECK(test_name, completed == 24);
}

void TestExportedEntryPoint()
{
    constexpr char test_name[] = "exported entry point";
    WSLPluginAPIV1 api = {};
    api.Version = {2, 5, 1};
    api.ExecuteBinaryInDistribution = &CaptureExecuteBinaryInDistribution;
    WSLPluginHooksV1 hooks = {};
    CHECK(test_name, WSLPLUGINAPI_ENTRYPOINTV1(&api, &hooks) == S_OK);
    CHECK(test_name, hooks.OnDistributionStarted != nullptr);

    api.Version = {2, 5, 0};
    hooks.OnDistributionStarted = &TestDistributionStarted;
    CHECK(test_name, WSLPLUGINAPI_ENTRYPOINTV1(&api, &hooks) == WSL_E_PLUGIN_REQUIRES_UPDATE);
    CHECK(test_name, hooks.OnDistributionStarted == nullptr);
}

} // namespace

int main()
{
    TestVersionGatingAndHookRegistration();
    TestRegistryPath();
    TestNonfatalEnablementAndLaunchFailures();
    TestRefreshLaunchArguments();
    TestSocketOwnershipAndRepeatedCallbacks();
    TestExportedEntryPoint();

    if (g_failures == 0)
    {
        std::puts("All plugin tests passed.");
    }

    return g_failures == 0 ? 0 : 1;
}
