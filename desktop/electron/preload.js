const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kothDesktop', {
  isElectron: true,
  backendUrl: 'http://127.0.0.1:5000',
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  getUserDataPath: () => ipcRenderer.invoke('get-userdata-path'),
  getBackendStatus: () => ipcRenderer.invoke('get-backend-status'),
  getServerNetworkInfo: () => ipcRenderer.invoke('get-server-network-info'),
  openLogsFolder: () => ipcRenderer.invoke('open-logs-folder'),
  openUserDataFolder: () => ipcRenderer.invoke('open-userdata-folder'),
});
