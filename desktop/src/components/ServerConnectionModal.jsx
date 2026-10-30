import React, { useState, useEffect } from 'react';
import {
  Server,
  Radio,
  Wifi,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  X,
  Shield,
  Activity,
  ArrowRight,
} from 'lucide-react';

export default function ServerConnectionModal({
  isOpen,
  onClose,
  currentUrl,
  onSaveConfig,
  isFirstLaunch = false,
}) {
  const [mode, setMode] = useState('CLIENT'); // 'HOST' | 'CLIENT'
  const [serverHost, setServerHost] = useState('');
  const [serverPort, setServerPort] = useState(5000);
  const [serverProtocol, setServerProtocol] = useState('http');
  const [ignoreCertErrors, setIgnoreCertErrors] = useState(true);
  const [testStatus, setTestStatus] = useState(null); // null | { testing, ok, latencyMs, message }
  const [saving, setSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [networkInfo, setNetworkInfo] = useState(null);

  useEffect(() => {
    // Load current config from Electron IPC or parse currentUrl
    const loadConfig = async () => {
      try {
        if (window.kothDesktop && window.kothDesktop.getClientConfig) {
          const cfg = await window.kothDesktop.getClientConfig();
          if (cfg) {
            setMode(cfg.appMode === 'HOST' ? 'HOST' : 'CLIENT');
            if (cfg.serverHost) setServerHost(cfg.serverHost);
            if (cfg.serverPort) setServerPort(cfg.serverPort);
            if (cfg.serverProtocol) setServerProtocol(cfg.serverProtocol);
            if (cfg.ignoreCertErrors !== undefined) setIgnoreCertErrors(cfg.ignoreCertErrors);
          }
        } else if (currentUrl) {
          try {
            const u = new URL(currentUrl);
            setServerProtocol(u.protocol.replace(':', ''));
            setServerHost(u.hostname);
            setServerPort(parseInt(u.port, 10) || 5000);
          } catch {}
        }

        if (window.kothDesktop && window.kothDesktop.getServerNetworkInfo) {
          const net = await window.kothDesktop.getServerNetworkInfo();
          setNetworkInfo(net);
          if (!serverHost && net?.primaryLanIp) {
            setServerHost(net.primaryLanIp);
          }
        }
      } catch (err) {
        console.error('Failed to load server config:', err);
      }
    };

    if (isOpen || isFirstLaunch) {
      loadConfig();
    }
  }, [isOpen, isFirstLaunch, currentUrl]);

  if (!isOpen && !isFirstLaunch) return null;

  const handleTestConnection = async () => {
    setTestStatus({ testing: true, ok: false, message: 'Probing central coordinator...' });
    setErrorMsg('');

    const hostToTest = mode === 'HOST' ? '127.0.0.1' : (serverHost.trim() || '127.0.0.1');
    const protoToTest = serverProtocol;
    const portToTest = Number(serverPort) || 5000;

    try {
      if (window.kothDesktop && window.kothDesktop.testServerConnection) {
        const res = await window.kothDesktop.testServerConnection({
          protocol: protoToTest,
          host: hostToTest,
          port: portToTest,
          ignoreCertErrors,
        });

        if (res.reachable) {
          setTestStatus({
            testing: false,
            ok: true,
            latencyMs: res.latencyMs,
            message: `Connection Verified (${res.latencyMs}ms) — Coordinator Instance: ${res.data?.coordinator_instance_id || 'Active'}`,
          });
        } else {
          setTestStatus({
            testing: false,
            ok: false,
            latencyMs: res.latencyMs,
            message: `Connection failed: ${res.error || 'Server unreachable on port ' + portToTest}`,
          });
        }
      } else {
        // Browser fallback test
        const testUrl = `${protoToTest}://${hostToTest}:${portToTest}/healthz`;
        const t0 = Date.now();
        const r = await fetch(testUrl, { method: 'GET' });
        const latencyMs = Date.now() - t0;
        if (r.ok) {
          const data = await r.json();
          setTestStatus({
            testing: false,
            ok: true,
            latencyMs,
            message: `Connected (${latencyMs}ms) — Coordinator: ${data.coordinator_instance_id || 'Active'}`,
          });
        } else {
          setTestStatus({
            testing: false,
            ok: false,
            message: `HTTP ${r.status} ${r.statusText}`,
          });
        }
      }
    } catch (err) {
      setTestStatus({
        testing: false,
        ok: false,
        message: `Failed: ${err.message}`,
      });
    }
  };

  const handleSave = async (e) => {
    if (e) e.preventDefault();
    setErrorMsg('');
    setSaving(true);

    const cleanHost = mode === 'HOST' ? '127.0.0.1' : (serverHost.trim() || '127.0.0.1');
    const cleanPort = Number(serverPort) || 5000;
    const newConfig = {
      configured: true,
      appMode: mode,
      serverHost: cleanHost,
      serverPort: cleanPort,
      serverProtocol,
      ignoreCertErrors,
    };

    const targetUrl = `${serverProtocol}://${cleanHost}:${cleanPort}`;

    try {
      if (window.kothDesktop && window.kothDesktop.saveClientConfig) {
        await window.kothDesktop.saveClientConfig(newConfig);
      }
      if (onSaveConfig) {
        onSaveConfig(newConfig, targetUrl);
      }
      if (onClose) {
        onClose();
      }
    } catch (err) {
      setErrorMsg(`Failed to save configuration: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(4px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: 620,
          backgroundColor: '#FFFFFF',
          borderRadius: 10,
          boxShadow: 'var(--shadow-md)',
          padding: 24,
          maxHeight: '90vh',
          overflowY: 'auto',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 8,
                backgroundColor: 'var(--bg-light-blue)',
                color: 'var(--accent-interactive-blue)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Wifi size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                {isFirstLaunch ? 'KOTH Command — Central Server Setup' : 'Central Server Connection Settings'}
              </h2>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Select role: Host the central server or connect as a participant desktop client.
              </div>
            </div>
          </div>
          {!isFirstLaunch && onClose && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={onClose}
              style={{ padding: 4, color: 'var(--text-secondary)' }}
            >
              <X size={16} />
            </button>
          )}
        </div>

        {/* Mode Selector Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
          {/* Card A: Host Server */}
          <div
            onClick={() => setMode('HOST')}
            style={{
              border: `2px solid ${mode === 'HOST' ? 'var(--accent-interactive-blue)' : 'var(--border-color)'}`,
              backgroundColor: mode === 'HOST' ? 'var(--bg-light-blue)' : '#FFFFFF',
              borderRadius: 8,
              padding: 14,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Server size={18} color={mode === 'HOST' ? 'var(--accent-interactive-blue)' : 'var(--text-secondary)'} />
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>Host Server</div>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Designated Central PC. Spawns authoritative coordinator, task manager, and SQLite database on 0.0.0.0:5000.
            </div>
          </div>

          {/* Card B: Connect to Server */}
          <div
            onClick={() => setMode('CLIENT')}
            style={{
              border: `2px solid ${mode === 'CLIENT' ? 'var(--accent-interactive-blue)' : 'var(--border-color)'}`,
              backgroundColor: mode === 'CLIENT' ? 'var(--bg-light-blue)' : '#FFFFFF',
              borderRadius: 8,
              padding: 14,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Radio size={18} color={mode === 'CLIENT' ? 'var(--accent-interactive-blue)' : 'var(--text-secondary)'} />
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>Participant Client</div>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Teammate / Operator PC. Connects over LAN. Never accesses SQLite directly; synchronizes all live state via API.
            </div>
          </div>
        </div>

        {/* Configuration Body */}
        {mode === 'HOST' ? (
          <div
            style={{
              backgroundColor: 'var(--bg-main)',
              borderRadius: 8,
              padding: 16,
              border: '1px solid var(--border-color)',
              marginBottom: 20,
            }}
          >
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 8 }}>
              Central Operations Host Parameters
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
              The backend service will bind to all network interfaces (<code style={{ color: 'var(--accent-interactive-blue)' }}>0.0.0.0:{serverPort}</code>) to allow remote teammate clients to connect.
            </div>
            {networkInfo && (
              <div style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 10 }}>
                <strong>Detected LAN IP:</strong> <code style={{ color: 'var(--accent-interactive-blue)' }}>{networkInfo.primaryLanIp}:{serverPort}</code>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                  Provide this address to your teammates so they can connect their desktop clients.
                </div>
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ flex: 1 }}>
                <label className="label">Service Port</label>
                <input
                  type="number"
                  className="input"
                  value={serverPort}
                  onChange={(e) => setServerPort(e.target.value)}
                  style={{ width: '100%' }}
                />
              </div>
            </div>
          </div>
        ) : (
          <div
            style={{
              backgroundColor: 'var(--bg-main)',
              borderRadius: 8,
              padding: 16,
              border: '1px solid var(--border-color)',
              marginBottom: 20,
            }}
          >
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 12 }}>
              Central Server Connection Parameters
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 100px', gap: 10, marginBottom: 14 }}>
              <div>
                <label className="label">Protocol</label>
                <select
                  className="input"
                  value={serverProtocol}
                  onChange={(e) => setServerProtocol(e.target.value)}
                  style={{ width: '100%' }}
                >
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </div>

              <div>
                <label className="label">Server Hostname or LAN IP</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. 192.168.1.100 or central.local"
                  value={serverHost}
                  onChange={(e) => setServerHost(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div>
                <label className="label">Port</label>
                <input
                  type="number"
                  className="input"
                  value={serverPort}
                  onChange={(e) => setServerPort(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <input
                type="checkbox"
                id="ignoreCert"
                checked={ignoreCertErrors}
                onChange={(e) => setIgnoreCertErrors(e.target.checked)}
              />
              <label htmlFor="ignoreCert" style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                Trust LAN SSL / Self-signed certificate (Recommended for local competition networks)
              </label>
            </div>

            {/* Test Connection Button */}
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleTestConnection}
              disabled={testStatus?.testing}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              {testStatus?.testing ? <RefreshCw size={13} className="spin" /> : <Activity size={13} />}
              Test Connection
            </button>
          </div>
        )}

        {/* Test Connection Status Banner */}
        {testStatus && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 6,
              marginBottom: 16,
              fontSize: 12,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              backgroundColor: testStatus.ok ? 'rgba(22, 163, 106, 0.1)' : 'rgba(220, 85, 85, 0.1)',
              border: `1px solid ${testStatus.ok ? 'var(--status-success)' : 'var(--status-critical)'}`,
              color: testStatus.ok ? 'var(--status-success)' : 'var(--status-critical)',
            }}
          >
            {testStatus.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            <span>{testStatus.message}</span>
          </div>
        )}

        {/* Error Message */}
        {errorMsg && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 6,
              marginBottom: 16,
              fontSize: 12,
              backgroundColor: 'rgba(220, 85, 85, 0.1)',
              border: '1px solid var(--status-critical)',
              color: 'var(--status-critical)',
            }}
          >
            {errorMsg}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
          {!isFirstLaunch && onClose && (
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
          )}
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleSave}
            disabled={saving || (mode === 'CLIENT' && !serverHost.trim())}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
          >
            {saving ? <RefreshCw size={14} className="spin" /> : <ArrowRight size={14} />}
            {mode === 'HOST' ? 'Start Central Server' : 'Connect to Central Server'}
          </button>
        </div>
      </div>
    </div>
  );
}
