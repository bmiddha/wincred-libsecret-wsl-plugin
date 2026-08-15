function Import-VisualStudioEnvironment
{
    [CmdletBinding()]
    param()

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path -LiteralPath $vswhere))
    {
        throw "Visual Studio Installer's vswhere.exe was not found."
    }

    $env:PATH = "$(Split-Path -Parent $vswhere);$env:PATH"
    $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$installationPath)
    {
        throw "Visual Studio with the C++ toolchain was not found."
    }

    $vsDevCmd = Join-Path $installationPath "Common7\Tools\VsDevCmd.bat"
    if (!(Test-Path -LiteralPath $vsDevCmd))
    {
        throw "VsDevCmd.bat was not found at '$vsDevCmd'."
    }

    $environment = & $env:ComSpec /s /c "`"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0)
    {
        throw "Visual Studio developer environment initialization failed."
    }

    foreach ($entry in $environment)
    {
        if ($entry -match "^([^=]+)=(.*)$")
        {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }

    return $installationPath
}
