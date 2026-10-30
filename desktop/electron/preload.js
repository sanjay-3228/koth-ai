const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kothDesktop', {
  isElectron: true,
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  getUserDataPath: () => ipcRenderer.invoke('get-userdata-path'),
  getBackendStatus: () => ipcRenderer.invoke('get-backend-status'),
  getServerNetworkInfo: () => ipcRenderer.invoke('get-server-network-info'),
  openLogsFolder: () => ipcRenderer.invoke('open-logs-folder'),
  openUserDataFolder: () => ipcRenderer.invoke('open-userdata-folder'),

  // Client & Server Configuration
  getClientConfig: () => ipcRenderer.invoke('get-client-config'),
  saveClientConfig: (config) => ipcRenderer.invoke('save-client-config', config),
  testServerConnection: (params) => ipcRenderer.invoke('test-server-connection', params),

  // Local Agent Worker Management
  startLocalWorker: (params) => ipcRenderer.invoke('start-local-worker', params),
  stopLocalWorker: () => ipcRenderer.invoke('stop-local-worker'),
  getLocalWorkerStatus: () => ipcRenderer.invoke('get-local-worker-status'),
});
