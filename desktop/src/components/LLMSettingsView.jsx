import React, { useState, useEffect, useCallback } from 'react';
import { Bot, Lock, CheckCircle2, AlertTriangle, Zap, Save, RefreshCw } from 'lucide-react';

export default function LLMSettingsView({
  user,
  coordinatorUrl,
  headers,
}) {
  const isLeader = user?.role === 'LEADER';
  const assignedAgentId = user?.agent_id || 'agent-01';

  // Selected agent sub-tab (defaults to current user's agent)
  const [selectedAgent, setSelectedAgent] = useState(assignedAgentId);

  const [llmConfig, setLlmConfig] = useState({
    provider: 'none',
    endpoint: '',
    model_id: '',
    api_key: '',
    enabled: false,
    connection_status: 'UNCONFIGURED',
    last_tested_at: null,
    last_error: null,
  });

  const [newApiKey, setNewApiKey] = useState('');
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saveStatus, setSaveStatus] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const isAssigned = user?.agent_id === selectedAgent;

  const defaults = {
    none: { endpoint: '', model: '' },
    openai: { endpoint: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
    anthropic: { endpoint: 'https://api.anthropic.com/v1', model: 'claude-3-5-sonnet-20241022' },
    gemini: { endpoint: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-1.5-flash' },
    custom: { endpoint: 'http://localhost:11434/v1', model: 'llama3' },
    local_simulated: { endpoint: 'local://simulated', model: 'simulated-advisory' },
  };

  const fetchConfig = useCallback(async () => {
    if (!isAssigned || !coordinatorUrl || !headers) return;
    try {
      const res = await fetch(`${coordinatorUrl}/api/agent/${selectedAgent}/llm`, {
        headers: headers(),
      });
      if (res.ok) {
        const data = await res.json();
        setLlmConfig(data);
        setErrorMsg('');
      } else if (res.status === 403) {
        setErrorMsg(`Access Denied: You are authenticated as '${user?.agent_id}', which cannot view '${selectedAgent}'.`);
      }
    } catch (err) {
      setErrorMsg(`Failed to load LLM config: ${err.message}`);
    }
  }, [coordinatorUrl, selectedAgent, isAssigned, user, headers]);

  useEffect(() => {
    setTestResult(null);
    setSaveStatus('');
    setErrorMsg('');
    setNewApiKey('');
    if (isAssigned) {
      fetchConfig();
    }
  }, [selectedAgent, isAssigned, fetchConfig]);

  const handleProviderSelect = (prov) => {
    const def = defaults[prov] || { endpoint: '', model: '' };
    setLlmConfig((prev) => ({
      ...prev,
      provider: prov,
      endpoint: def.endpoint,
      model_id: def.model,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveStatus('');
    setErrorMsg('');
    try {
      const payload = {
        provider: llmConfig.provider,
        endpoint: llmConfig.endpoint,
        model_id: llmConfig.model_id,
        enabled: llmConfig.enabled,
      };
      if (newApiKey.trim()) {
        payload.api_key = newApiKey.trim();
      }

      const res = await fetch(`${coordinatorUrl}/api/agent/${selectedAgent}/llm`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to save configuration');
      setLlmConfig(data);
      setNewApiKey('');
      setSaveStatus('LLM configuration saved successfully.');
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    setErrorMsg('');
    try {
      const payload = {
        provider: llmConfig.provider,
        endpoint: llmConfig.endpoint,
        model_id: llmConfig.model_id,
        enabled: llmConfig.enabled,
      };
      if (newApiKey.trim()) {
        payload.api_key = newApiKey.trim();
      }

      const res = await fetch(`${coordinatorUrl}/api/agent/${selectedAgent}/llm/test`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Connection test failed');
      setTestResult(data);
      setLlmConfig((prev) => ({
        ...prev,
        connection_status: data.status,
        last_tested_at: Date.now() / 1000,
      }));
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setTesting(false);
    }
  };

  const statusBadge = {
    CONNECTED: 'badge-green',
    FAILED: 'badge-red',
    DISABLED: 'badge-yellow',
    UNCONFIGURED: 'badge-neutral',
  }[llmConfig.connection_status] || 'badge-neutral';

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Agent LLM Settings & Isolation</h1>
          <p className="view-subtitle">
            Independent, advisory-only model integrations per agent with zero credential leakage
          </p>
        </div>
      </div>

      {/* Agent Selector Sub-Tabs */}
      <div className="sub-tabs">
        {['agent-01', 'agent-02', 'agent-03', 'agent-04'].map((aid, idx) => {
          const isUserAgent = user?.agent_id === aid;
          return (
            <button
              key={aid}
              type="button"
              className={`sub-tab-btn ${selectedAgent === aid ? 'active' : ''}`}
              onClick={() => setSelectedAgent(aid)}
            >
              {aid} (Hill {idx + 1}) {isUserAgent ? '— (Your Agent)' : ''}
            </button>
          );
        })}
      </div>

      {/* Main Configuration Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Bot size={18} />
            <span>LLM Advisory Configuration: {selectedAgent}</span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className={`badge ${statusBadge}`}>
              Status: {llmConfig.connection_status}
            </span>
            {isAssigned && (
              <button type="button" onClick={fetchConfig} className="btn-sm">
                <RefreshCw size={12} />
              </button>
            )}
          </div>
        </div>

        {!isAssigned ? (
          <div className="alert-banner alert-danger">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Lock size={18} />
              <div>
                <strong>Cross-Agent LLM Isolation Enforced</strong>
                <div style={{ fontSize: 12, marginTop: 2 }}>
                  You are authenticated as <strong>{user?.agent_id}</strong>. Backend RBAC prohibits reading or modifying LLM configurations for <strong>{selectedAgent}</strong>.
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
              All LLM recommendations for <strong>{selectedAgent}</strong> are advisory. All task actions must pass deterministic security execution gates.
            </p>

            {saveStatus && (
              <div className="alert-banner alert-success" style={{ marginBottom: 14 }}>
                <CheckCircle2 size={16} />
                <span>{saveStatus}</span>
              </div>
            )}

            {errorMsg && (
              <div className="alert-banner alert-danger" style={{ marginBottom: 14 }}>
                <AlertTriangle size={16} />
                <span>{errorMsg}</span>
              </div>
            )}

            {testResult && (
              <div className={`alert-banner ${testResult.success ? 'alert-success' : 'alert-danger'}`} style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {testResult.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                  <span>
                    {testResult.message} ({testResult.latency_ms}ms)
                  </span>
                </div>
              </div>
            )}

            <div className="grid-2">
              {/* Left Column: Model Parameters */}
              <div>
                <label htmlFor="llm-provider">Model Provider</label>
                <select
                  id="llm-provider"
                  value={llmConfig.provider}
                  onChange={(e) => handleProviderSelect(e.target.value)}
                >
                  <option value="none">None (Deterministic Only · No LLM)</option>
                  <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
                  <option value="anthropic">Anthropic (Claude 3.5 Sonnet / Haiku)</option>
                  <option value="gemini">Google Gemini (Gemini 1.5 Flash / Pro)</option>
                  <option value="custom">Custom Compatible API (Ollama / vLLM / REST)</option>
                  <option value="local_simulated">Local Simulated Adapter (Rehearsal / Test)</option>
                </select>

                <label htmlFor="llm-endpoint">Endpoint / Base URL</label>
                <input
                  id="llm-endpoint"
                  type="text"
                  placeholder={defaults[llmConfig.provider]?.endpoint || 'https://api.openai.com/v1'}
                  value={llmConfig.endpoint}
                  onChange={(e) => setLlmConfig((prev) => ({ ...prev, endpoint: e.target.value }))}
                />

                <label htmlFor="llm-model">Model Identifier</label>
                <input
                  id="llm-model"
                  type="text"
                  placeholder={defaults[llmConfig.provider]?.model || 'gpt-4o-mini'}
                  value={llmConfig.model_id}
                  onChange={(e) => setLlmConfig((prev) => ({ ...prev, model_id: e.target.value }))}
                />
              </div>

              {/* Right Column: Credentials & Toggles */}
              <div>
                <label htmlFor="llm-api-key">
                  API Key {llmConfig.api_key && <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>({llmConfig.api_key})</span>}
                </label>
                <input
                  id="llm-api-key"
                  type="password"
                  placeholder={llmConfig.api_key ? 'Leave empty to preserve existing key' : 'Enter user-supplied API key'}
                  value={newApiKey}
                  onChange={(e) => setNewApiKey(e.target.value)}
                />
                <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: -6, marginBottom: 14 }}>
                  🔒 Zero token leakage: Keys are masked in responses, redacted from logs, and never sent in prompts.
                </p>

                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18, marginTop: 10 }}>
                  <input
                    type="checkbox"
                    id={`llm-enable-${selectedAgent}`}
                    style={{ width: 'auto', margin: 0, cursor: 'pointer' }}
                    checked={llmConfig.enabled}
                    onChange={(e) => setLlmConfig((prev) => ({ ...prev, enabled: e.target.checked }))}
                  />
                  <label htmlFor={`llm-enable-${selectedAgent}`} style={{ fontSize: 13, cursor: 'pointer', margin: 0 }}>
                    Enable Advisory Recommendations for {selectedAgent}
                  </label>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 14 }}>
                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testing || llmConfig.provider === 'none'}
                    style={{ flex: 1 }}
                  >
                    <Zap size={13} />
                    <span>{testing ? 'Testing...' : 'Test Connection'}</span>
                  </button>

                  <button
                    type="button"
                    className="btn-primary"
                    onClick={handleSave}
                    disabled={saving}
                    style={{ flex: 1 }}
                  >
                    <Save size={13} />
                    <span>{saving ? 'Saving...' : 'Save Settings'}</span>
                  </button>
                </div>

                {llmConfig.last_error && (
                  <div style={{ fontSize: 12, color: 'var(--color-error)', marginTop: 10, wordBreak: 'break-all' }}>
                    Last Error: {llmConfig.last_error}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

