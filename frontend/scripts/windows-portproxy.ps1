param(
  [int]$Port = 5173,
  [string]$ListenAddress = "127.0.0.1",
  [string]$Distro = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Port -le 0) {
  throw "Port 必须大于 0。"
}

function Get-WslIp {
  param([string]$TargetDistro)

  if ([string]::IsNullOrWhiteSpace($TargetDistro)) {
    $raw = & wsl.exe -- bash -lc "hostname -I | awk '{print \$1}'"
  }
  else {
    $raw = & wsl.exe -d $TargetDistro -- bash -lc "hostname -I | awk '{print \$1}'"
  }

  $ip = ($raw | Select-Object -First 1).ToString().Trim()
  if ([string]::IsNullOrWhiteSpace($ip)) {
    throw "无法解析 WSL IP。请先确认目标发行版已启动。"
  }

  return $ip
}

$wslIp = Get-WslIp -TargetDistro $Distro

Write-Host "WSL IP: $wslIp"
Write-Host "Refreshing Windows portproxy for http://${ListenAddress}:$Port ..."

& netsh interface portproxy delete v4tov4 listenaddress=$ListenAddress listenport=$Port | Out-Null
& netsh interface portproxy add v4tov4 listenaddress=$ListenAddress listenport=$Port connectaddress=$wslIp connectport=$Port | Out-Null

Write-Host ""
Write-Host "Windows 映射已更新："
Write-Host "  http://${ListenAddress}:$Port"
Write-Host ""
Write-Host "如果你还需要让局域网其他设备访问，请自行把 listenaddress 改成 0.0.0.0 并按需放行防火墙。"
