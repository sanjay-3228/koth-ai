const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn, exec } = require('child_process');
const os = require('os');

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
    port: 5000,
    lanAddresses,
    primaryLanIp: primaryIp,
    apiBaseUrl: `http://${primaryIp}:5000`,
  };
}

// Enforce single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

let mainWindow = null;
let backendProcess = null;
let backendSpawnedByUs = false;

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

function checkBackendHealth(url = 'http://127.0.0.1:5000/healthz', timeoutMs = 800) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
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
                      `Database: ${dbPath}\n` +
                      `Logs: ${backendLogFile}\n` +
                      `======================================================\n`;
  logStream.write(startBanner);

  const spawnArgs = [
    '--port', '5000',
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
  }
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
    // Fallback directly to local coordinator admin UI
    mainWindow.loadURL('http://127.0.0.1:5000/admin');
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

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
}));
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

  // Launch backend service before opening main UI
  const backendOk = await startBackendService();
  if (!backendOk) {
    dialog.showMessageBoxSync({
      type: 'warning',
      title: 'KOTH Command — Coordinator Notice',
      message: 'The KOTH Swarm Coordinator could not be started automatically on port 5000.',
      detail: `Database path: ${dbPath}\nLog path: ${backendLogFile}\n\nThe application will attempt to load the interface in standalone mode. If an external coordinator is running, connection will be established automatically.`,
      buttons: ['OK'],
    });
  }

  createMainWindow();
});

// App lifecycle events
app.on('before-quit', () => {
  stopBackendService();
});

app.on('will-quit', () => {
  stopBackendService();
});

app.on('window-all-closed', () => {
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
