#!/usr/bin/env node

const childProcess = require('child_process');

const BINARY_MAP = {
  darwin_x64: {name: 'kubernetes-mcp-server-darwin-amd64', suffix: ''},
  darwin_arm64: {name: 'kubernetes-mcp-server-darwin-arm64', suffix: ''},
  linux_x64: {name: 'kubernetes-mcp-server-linux-amd64', suffix: ''},
  linux_arm64: {name: 'kubernetes-mcp-server-linux-arm64', suffix: ''},
  win32_x64: {name: 'kubernetes-mcp-server-windows-amd64', suffix: '.exe'},
  win32_arm64: {name: 'kubernetes-mcp-server-windows-arm64', suffix: '.exe'},
};

// Resolving will fail if the optionalDependency was not installed or the platform/arch is not supported
const resolveBinaryPath = () => {
  try {
    const binary = BINARY_MAP[`${process.platform}_${process.arch}`];
    return require.resolve(`${binary.name}/bin/${binary.name}${binary.suffix}`);
  } catch (e) {
    throw new Error(`Could not resolve binary path for platform/arch: ${process.platform}/${process.arch}`);
  }
};

const child = childProcess.spawn(resolveBinaryPath(), process.argv.slice(2), {
  stdio: 'inherit',
});

const handleSignal = () => (signal) => {
  console.log(`Received ${signal}, terminating child process...`);
  if (child && !child.killed) {
    child.kill(signal);
  }
};

['SIGTERM', 'SIGINT', 'SIGHUP'].forEach((signal) => {
  process.on(signal, handleSignal(signal));
});

child.on('close', (code, signal) => {
  if (signal) {
    console.log(`Child process terminated by signal: ${signal}`);
    process.exit(128 + (signal === 'SIGTERM' ? 15 : signal === 'SIGINT' ? 2 : 1));
  } else {
    process.exit(code || 0);
  }
});
