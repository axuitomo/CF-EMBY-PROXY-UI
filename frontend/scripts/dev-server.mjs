import { spawn } from 'node:child_process';
import os from 'node:os';
import process from 'node:process';

function resolvePort() {
  const rawValue = Number(process.env.PORT || process.env.VITE_DEV_PORT || 5173);
  return Number.isFinite(rawValue) && rawValue > 0 ? rawValue : 5173;
}

function resolveWslIpv4() {
  const networks = os.networkInterfaces();
  const candidates = [];

  for (const [name, entries] of Object.entries(networks)) {
    for (const entry of entries || []) {
      if (!entry || entry.internal || entry.family !== 'IPv4') continue;
      candidates.push({ name, address: entry.address });
    }
  }

  const preferred = candidates.find((item) => item.name === 'eth0')
    || candidates.find((item) => item.name.startsWith('en'))
    || candidates[0];

  return preferred?.address || '';
}

const port = resolvePort();
const vendorMode = String(process.env.VITE_VENDOR_MODE || 'bundle').trim() || 'bundle';
const wslIpv4 = resolveWslIpv4();

console.log('');
console.log(`[dev] Vendor mode: ${vendorMode}`);
console.log(`[dev] WSL local: http://127.0.0.1:${port}`);
console.log(`[dev] Windows browser: http://localhost:${port}`);
if (wslIpv4) {
  console.log(`[dev] WSL fallback IP: http://${wslIpv4}:${port}`);
}
console.log('[dev] 如果 Windows 无法通过 localhost 访问，可在 Windows PowerShell 中运行：');
console.log(`[dev]   powershell -ExecutionPolicy Bypass -File .\\frontend\\scripts\\windows-portproxy.ps1 -Port ${port}`);
console.log('');

const child = spawn(
  process.platform === 'win32' ? 'vite.cmd' : 'vite',
  ['--host', '0.0.0.0', '--port', String(port)],
  {
    stdio: 'inherit',
    env: {
      ...process.env,
      VITE_VENDOR_MODE: vendorMode
    }
  }
);

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});
