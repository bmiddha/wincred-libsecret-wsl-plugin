[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

foreach ($name in @(
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_ARTIFACT_SIGNING_ENDPOINT",
    "AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME",
    "AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME"
))
{
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name)))
    {
        throw "GitHub release environment variable '$name' must be configured."
    }
}
