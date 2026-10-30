const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { spawn, exec } = require('child_process');
const os = require('os');

// Enforce single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

let mainWindow = null;
let backendProcess = null;
let backendSpawnedByUs = false;
let localWorkerProcess = null;
let localWorkerInfo = {
  running: false,
  pid: null,
  agentId: null,
  teamId: null,
  startTime: null,
  error: null,
};

// Application paths & persistence setup
const userDataPath = app.getPath('userData');
if (!fs.existsSync(userDataPath)) {
  fs.mkdirSync(userDataPath, { recursive: true });
}
const logsDir = path.join(userDataPath, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}
const dbPath = path.join(userDataPath, 'koth_swarm.db');
const backendLogFile = path.join(logsDir, 'coordinator.log');
const clientConfigFile = path.join(userDataPath, 'client_config.json');

// Client configuration loader and saver
function loadClientConfig() {
  try {
    if (fs.existsSync(clientConfigFile)) {
      const data = JSON.parse(fs.readFileSync(clientConfigFile, 'utf8'));
      return {
        configured: data.configured !== undefined ? data.configured : true,
        appMode: data.appMode || 'HOST', // 'HOST' | 'CLIENT' | 'UNCONFIGURED'
        serverHost: data.serverHost || '127.0.0.1',
        serverPort: data.serverPort || 5000,
        serverProtocol: data.serverProtocol || 'http',
        ignoreCertErrors: Boolean(data.ignoreCertErrors),
        caCertPath: data.caCertPath || '',
      };
    }
  } catch (err) {
    console.error('[KOTH Main] Error loading client_config.json:', err);
  }
  return {
    configured: false,
    appMode: 'UNCONFIGURED',
    serverHost: '127.0.0.1',
    serverPort: 5000,
    serverProtocol: 'http',
    ignoreCertErrors: false,
    caCertPath: '',
  };
}

let currentConfig = loadClientConfig();

function saveClientConfigFile(newConfig) {
  try {
    currentConfig = { ...currentConfig, ...newConfig, configured: true };
    fs.writeFileSync(clientConfigFile, JSON.stringify(currentConfig, null, 2), 'utf8');
    console.log('[KOTH Main] Client configuration saved:', currentConfig);
    return true;
  } catch (err) {
    console.error('[KOTH Main] Failed to write client_config.json:', err);
    return false;
  }
}

function getServerNetworkInfo() {
  const interfaces = os.networkInterfaces();
  const lanAddresses = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        lanAddresses.push({
          interface: name,
          ip: iface.address,
        });
      }
    }
  }
  const primaryIp = lanAddresses.length > 0 ? lanAddresses[0].ip : '127.0.0.1';
  return {
    hostname: os.hostname(),
    port: currentConfig.serverPort || 5000,
    lanAddresses,
    primaryLanIp: primaryIp,
    apiBaseUrl: `${currentConfig.serverProtocol || 'http'}://${primaryIp}:${currentConfig.serverPort || 5000}`,
    appMode: currentConfig.appMode,
  };
}

function getBackendExecutablePath() {
  const candidatePaths = [
    // 1. Packaged Electron resources directory (electron-builder extraResources)
    path.join(process.resourcesPath, 'backend', 'koth-coordinator.exe'),
    // 2. Relative to app path in packaged environment
    path.join(app.getAppPath(), '..', 'backend', 'koth-coordinator.exe'),
    // 3. Development / repo backend-dist directory
    path.join(__dirname, '..', '..', 'backend-dist', 'koth-coordinator.exe'),
    path.join(__dirname, '..', 'backend-dist', 'koth-coordinator.exe'),
    path.join(process.cwd(), 'backend-dist', 'koth-coordinator.exe'),
  ];

  for (const candidate of candidatePaths) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function getAgentWorkerExecutablePath() {
  const candidatePaths = [
    // 1. Packaged Electron resources directory (electron-builder extraResources)
    path.join(process.resourcesPath, 'worker', 'koth-agent-worker.exe'),
    // 2. Relative to app path in packaged environment
    path.join(app.getAppPath(), '..', 'worker', 'koth-agent-worker.exe'),
    // 3. Development / repo agent-worker-dist directory
    path.join(__dirname, '..', '..', 'agent-worker-dist', 'koth-agent-worker.exe'),
    path.join(__dirname, '..', 'agent-worker-dist', 'koth-agent-worker.exe'),
    path.join(process.cwd(), 'agent-worker-dist', 'koth-agent-worker.exe'),
  ];

  for (const candidate of candidatePaths) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function checkBackendHealth(url = 'http://127.0.0.1:5000/healthz', timeoutMs = 800) {
  return new Promise((resolve) => {
    const isHttps = url.startsWith('https://');
    const client = isHttps ? https : http;
    const req = client.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function startBackendService() {
  const isAlreadyRunning = await checkBackendHealth();
  if (isAlreadyRunning) {
    console.log('[KOTH Main] Backend coordinator is already running and healthy on port 5000.');
    return true;
  }

  const exePath = getBackendExecutablePath();
  const logStream = fs.createWriteStream(backendLogFile, { flags: 'a' });
  const startBanner = `\n======================================================\n` +
                      `[KOTH Swarm Coordinator Launch: ${new Date().toISOString()}]\n` +
                      `Mode: CENTRAL SERVER (HOST)\n` +
                      `Database: ${dbPath}\n` +
                      `Logs: ${backendLogFile}\n` +
                      `======================================================\n`;
  logStream.write(startBanner);

  const spawnArgs = [
    '--port', String(currentConfig.serverPort || 5000),
    '--host', '0.0.0.0',
    '--db-path', dbPath,
    '--profile', 'LOCAL_REHEARSAL'
  ];

  if (exePath) {
    console.log(`[KOTH Main] Spawning coordinator binary: ${exePath}`);
    logStream.write(`Target Binary: ${exePath}\nArgs: ${spawnArgs.join(' ')}\n\n`);

    backendProcess = spawn(exePath, spawnArgs, {
      detached: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } else {
    // Development fallback to python
    console.warn('[KOTH Main] Binary not found. Attempting python backend_main.py fallback...');
    const pythonScript = path.join(__dirname, '..', '..', 'backend_main.py');
    if (!fs.existsSync(pythonScript)) {
      console.error('[KOTH Main] Neither koth-coordinator.exe nor backend_main.py was found.');
      return false;
    }
    logStream.write(`Fallback Python: ${pythonScript}\n\n`);
    backendProcess = spawn('python', [pythonScript, ...spawnArgs], {
      detached: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  backendSpawnedByUs = true;

  if (backendProcess.stdout) backendProcess.stdout.pipe(logStream);
  if (backendProcess.stderr) backendProcess.stderr.pipe(logStream);

  backendProcess.on('error', (err) => {
    console.error('[KOTH Main] Coordinator process error:', err);
    logStream.write(`[PROCESS ERROR]: ${err.message}\n`);
  });

  backendProcess.on('exit', (code, signal) => {
    console.log(`[KOTH Main] Coordinator exited with code ${code}, signal ${signal}`);
    logStream.write(`[PROCESS EXIT]: Code ${code}, Signal ${signal}\n`);
    backendProcess = null;
    backendSpawnedByUs = false;
  });

  // Poll for healthz endpoint readiness (up to 30s)
  const maxPolls = 60; // 60 * 500ms = 30 seconds
  for (let i = 0; i < maxPolls; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const healthy = await checkBackendHealth();
    if (healthy) {
      console.log(`[KOTH Main] Backend ready after ${(i + 1) * 0.5}s.`);
      return true;
    }
  }

  console.error('[KOTH Main] Timed out waiting for coordinator health check.');
  return false;
}

function stopBackendService() {
  if (backendProcess && backendSpawnedByUs) {
    const pid = backendProcess.pid;
    console.log(`[KOTH Main] Stopping coordinator process PID ${pid}...`);
    try {
      if (process.platform === 'win32') {
        exec(`taskkill /pid ${pid} /T /F`, (err) => {
          if (err && !err.message.includes('not found')) {
            console.error('[KOTH Main] taskkill error:', err.message);
          }
        });
      } else {
        backendProcess.kill('SIGTERM');
      }
    } catch (e) {
      console.error('[KOTH Main] Backend cleanup exception:', e);
    }
    backendProcess = null;
    backendSpawnedByUs = false;
  }
}

// Local Agent Worker Management
function startLocalWorkerSubprocess({ coordinatorUrl, agentId, teamId, sessionToken, token }) {
  if (localWorkerProcess && localWorkerInfo.running) {
    return { success: true, message: 'Local worker is already running', pid: localWorkerProcess.pid };
  }

  const workerExe = getAgentWorkerExecutablePath();
  const workerLogPath = path.join(logsDir, `local_worker_${agentId || 'agent-02'}.log`);
  const workerLogStream = fs.createWriteStream(workerLogPath, { flags: 'a' });

  const workerBanner = `\n======================================================\n` +
                       `[KOTH Local Agent Worker Launch: ${new Date().toISOString()}]\n` +
                       `Agent: ${agentId} | Team: ${teamId || 'null_warriors'}\n` +
                       `Server: ${coordinatorUrl}\n` +
                       `Logs: ${workerLogPath}\n` +
                       `======================================================\n`;
  workerLogStream.write(workerBanner);

  const spawnArgs = [
    '--server', coordinatorUrl,
    '--agent', agentId || 'agent-02',
    '--team', teamId || 'null_warriors',
  ];
  if (sessionToken) {
    spawnArgs.push('--session-token', sessionToken);
  } else if (token) {
    spawnArgs.push('--token', token);
  }

  try {
    if (workerExe) {
      console.log(`[KOTH Main] Spawning local agent worker binary: ${workerExe}`);
      workerLogStream.write(`Target Binary: ${workerExe}\nArgs: ${spawnArgs.join(' ')}\n\n`);
      localWorkerProcess = spawn(workerExe, spawnArgs, {
        detached: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      console.warn('[KOTH Main] Agent worker binary not found. Attempting python agent_worker_main.py...');
      const pythonScript = path.join(__dirname, '..', '..', 'agent_worker_main.py');
      if (!fs.existsSync(pythonScript)) {
        throw new Error('Neither koth-agent-worker.exe nor agent_worker_main.py was found.');
      }
      workerLogStream.write(`Fallback Python: ${pythonScript}\nArgs: ${spawnArgs.join(' ')}\n\n`);
      localWorkerProcess = spawn('python', [pythonScript, ...spawnArgs], {
        detached: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    }

    localWorkerInfo = {
      running: true,
      pid: localWorkerProcess.pid,
      agentId: agentId || 'agent-02',
      teamId: teamId || 'null_warriors',
      startTime: new Date().toISOString(),
      error: null,
    };

    if (localWorkerProcess.stdout) localWorkerProcess.stdout.pipe(workerLogStream);
    if (localWorkerProcess.stderr) localWorkerProcess.stderr.pipe(workerLogStream);

    localWorkerProcess.on('error', (err) => {
      console.error('[KOTH Main] Local agent worker process error:', err);
      localWorkerInfo.running = false;
      localWorkerInfo.error = err.message;
      workerLogStream.write(`[PROCESS ERROR]: ${err.message}\n`);
    });

    localWorkerProcess.on('exit', (code, signal) => {
      console.log(`[KOTH Main] Local agent worker exited with code ${code}, signal ${signal}`);
      workerLogStream.write(`[PROCESS EXIT]: Code ${code}, Signal ${signal}\n`);
      localWorkerProcess = null;
      localWorkerInfo.running = false;
      localWorkerInfo.pid = null;
    });

    return { success: true, pid: localWorkerProcess.pid, message: 'Local worker started successfully' };
  } catch (err) {
    console.error('[KOTH Main] Failed to spawn local agent worker:', err);
    localWorkerInfo.running = false;
    localWorkerInfo.error = err.message;
    return { success: false, error: err.message };
  }
}

function stopLocalWorkerSubprocess() {
  if (localWorkerProcess) {
    const pid = localWorkerProcess.pid;
    console.log(`[KOTH Main] Stopping local agent worker PID ${pid}...`);
    try {
      if (process.platform === 'win32') {
        exec(`taskkill /pid ${pid} /T /F`, (err) => {
          if (err && !err.message.includes('not found')) {
            console.error('[KOTH Main] taskkill error for worker:', err.message);
          }
        });
      } else {
        localWorkerProcess.kill('SIGTERM');
      }
    } catch (e) {
      console.error('[KOTH Main] Worker cleanup exception:', e);
    }
    localWorkerProcess = null;
  }
  localWorkerInfo.running = false;
  localWorkerInfo.pid = null;
  return { success: true };
}

function createMainWindow() {
  const iconPath = path.join(__dirname, '..', 'build', 'icon.ico');

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 920,
    minWidth: 1080,
    minHeight: 720,
    backgroundColor: '#F4F7FB',
    title: 'KOTH Command — Swarm Operations Center',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.setMenuBarVisibility(false);

  const distIndex = path.join(__dirname, '..', 'dist', 'index.html');
  const isDev = process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
  } else if (fs.existsSync(distIndex)) {
    mainWindow.loadFile(distIndex);
  } else {
    // Fallback to local admin
    mainWindow.loadURL('http://127.0.0.1:5000/admin');
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Handle TLS certificates for LAN deployment
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (currentConfig.ignoreCertErrors) {
    event.preventDefault();
    callback(true);
    return;
  }
  // Check if connecting to LAN IP or localhost
  const isLanOrLocal = url.includes('127.0.0.1') ||
                       url.includes('localhost') ||
                       url.includes('192.168.') ||
                       url.includes('10.') ||
                       url.includes('172.16.') ||
                       url.includes('172.17.') ||
                       url.includes('172.18.') ||
                       url.includes('172.19.') ||
                       url.includes('172.2') ||
                       url.includes('172.3');
  if (isLanOrLocal) {
    event.preventDefault();
    callback(true);
    return;
  }
  callback(false);
});

// IPC Handlers
ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('get-system-info', () => ({
  platform: process.platform,
  arch: process.arch,
  nodeVersion: process.versions.node,
  electronVersion: process.versions.electron,
  isPackaged: app.isPackaged,
}));
ipcMain.handle('get-userdata-path', () => userDataPath);
ipcMain.handle('get-server-network-info', () => getServerNetworkInfo());
ipcMain.handle('get-backend-status', async () => ({
  healthy: await checkBackendHealth(),
  backendSpawned: backendSpawnedByUs,
  dbPath,
  logsDir,
  logFile: backendLogFile,
  pid: backendProcess ? backendProcess.pid : null,
  appMode: currentConfig.appMode,
}));

// Client Configuration IPC Handlers
ipcMain.handle('get-client-config', () => currentConfig);

ipcMain.handle('save-client-config', async (event, newConfig) => {
  const oldMode = currentConfig.appMode;
  saveClientConfigFile(newConfig);

  // If switched to HOST and backend is not running, launch it
  if (currentConfig.appMode === 'HOST' && !backendProcess) {
    const ok = await startBackendService();
    return { success: true, backendReady: ok, config: currentConfig };
  }

  // If switched to CLIENT and backend was running, shut it down
  if (currentConfig.appMode === 'CLIENT' && backendProcess) {
    stopBackendService();
  }

  return { success: true, config: currentConfig };
});

ipcMain.handle('test-server-connection', (event, { protocol, host, port, ignoreCertErrors }) => {
  return new Promise((resolve) => {
    const proto = protocol || 'http';
    const h = host || '127.0.0.1';
    const p = port || 5000;
    const url = `${proto}://${h}:${p}/healthz`;
    const isHttps = proto === 'https';
    const client = isHttps ? https : http;

    const t0 = Date.now();
    const req = client.get(url, {
      timeout: 3000,
      rejectUnauthorized: !ignoreCertErrors,
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        const latencyMs = Date.now() - t0;
        if (res.statusCode === 200) {
          try {
            const data = JSON.parse(body);
            resolve({ reachable: true, statusCode: res.statusCode, latencyMs, data });
          } catch {
            resolve({ reachable: true, statusCode: res.statusCode, latencyMs, raw: body });
          }
        } else {
          resolve({ reachable: false, statusCode: res.statusCode, latencyMs, error: `HTTP ${res.statusCode}` });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ reachable: false, error: err.message, latencyMs: Date.now() - t0 });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ reachable: false, error: 'Connection timed out after 3000ms', latencyMs: 3000 });
    });
  });
});

// Local Worker Management IPC Handlers
ipcMain.handle('start-local-worker', (event, params) => startLocalWorkerSubprocess(params));
ipcMain.handle('stop-local-worker', () => stopLocalWorkerSubprocess());
ipcMain.handle('get-local-worker-status', () => localWorkerInfo);

ipcMain.handle('open-logs-folder', () => {
  shell.openPath(logsDir);
});
ipcMain.handle('open-userdata-folder', () => {
  shell.openPath(userDataPath);
});

// Second instance focus
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

app.whenReady().then(async () => {
  app.setAppUserModelId('com.koth.command');

  // Launch backend service ONLY if configured as HOST
  if (currentConfig.configured && currentConfig.appMode === 'HOST') {
    const backendOk = await startBackendService();
    if (!backendOk) {
      dialog.showMessageBoxSync({
        type: 'warning',
        title: 'KOTH Command — Coordinator Notice',
        message: 'The KOTH Swarm Coordinator could not be started automatically on port 5000.',
        detail: `Database path: ${dbPath}\nLog path: ${backendLogFile}\n\nThe application will attempt to load the interface in standalone mode.`,
        buttons: ['OK'],
      });
    }
  } else {
    console.log(`[KOTH Main] Running in ${currentConfig.appMode} mode (Central coordinator not spawned on this machine).`);
  }

  createMainWindow();
});

// App lifecycle events
app.on('before-quit', () => {
  stopLocalWorkerSubprocess();
  stopBackendService();
});

app.on('will-quit', () => {
  stopLocalWorkerSubprocess();
  stopBackendService();
});

app.on('window-all-closed', () => {
  stopLocalWorkerSubprocess();
  stopBackendService();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createMainWindow();
  }
});
