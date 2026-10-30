import React, { useState } from 'react';
import {
  Trophy,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Trash2,
  ChevronRight,
  ChevronLeft,
  Server,
  Flame,
  Swords,
  Play,
  RotateCcw,
} from 'lucide-react';

const HILL_ENVIRONMENT_TYPES = [
  { value: 'LINUX', label: 'Linux' },
  { value: 'WINDOWS', label: 'Windows' },
  { value: 'WEB_APPLICATION', label: 'Web Application' },
  { value: 'DATABASE', label: 'Database' },
  { value: 'NETWORK', label: 'Network' },
  { value: 'ACTIVE_DIRECTORY', label: 'Active Directory' },
  { value: 'CLOUD_SECURITY', label: 'Cloud Security' },
  { value: 'CONTAINER_K8S', label: 'Container/Kubernetes' },
  { value: 'FORENSICS_IR', label: 'Forensics/Incident Response' },
];

const KOTH_FORMATS = [
  { id: 'SINGLE_HILL', name: 'Single-Hill', desc: 'All squads contend for a solitary critical hill asset.' },
  { id: 'MULTI_HILL', name: 'Multi-Hill', desc: 'Multiple concurrent hills across diverse network targets.' },
  { id: 'TEAM_VS_TEAM', name: 'Team-vs-Team', desc: 'Direct bilateral squad confrontation over contested hills.' },
  { id: 'ELIMINATION', name: 'Elimination', desc: 'Squads eliminated upon dropping below threshold or losing all hills.' },
  { id: 'TIMED', name: 'Timed', desc: 'Fixed duration countdown; highest score at clock expiry wins.' },
];

const RVB_FORMATS = [
  { id: 'CLASSIC', name: 'Classic', desc: 'Symmetric attack and defense on allocated hill sectors.' },
  { id: 'MULTI_TEAM', name: 'Multi-Team', desc: 'Multiple Red teams collaborate against multiple Blue teams.' },
  { id: 'MULTI_HILL', name: 'Multi-Hill', desc: 'Contested matrix across heterogeneous multi-service hills.' },
  { id: 'ELIMINATION', name: 'Elimination', desc: 'Sides eliminated upon catastrophic infrastructure loss.' },
  { id: 'TIMED', name: 'Timed', desc: 'Strict time limit; highest cumulative side score wins.' },
  { id: 'CONTINUOUS', name: 'Continuous Attack and Defense', desc: 'Uninterrupted tick scoring with dynamic recapture cycles.' },
];

export default function CompetitionWizard({
  coordinatorUrl,
  headers,
  initialMode = 'RED_VS_BLUE',
  initialFormat,
  onCompetitionCreated,
  onCancel,
}) {
  // Exactly 4 Steps: 1 (Mode & Format), 2 (Target Hills), 3 (Review), 4 (Launch)
  const [currentStep, setCurrentStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // STEP 1: MODE & FORMAT
  const [mode, setMode] = useState(initialMode); // 'KOTH' | 'RED_VS_BLUE'
  const [format, setFormat] = useState(
    initialFormat || (initialMode === 'KOTH' ? 'SINGLE_HILL' : 'CLASSIC')
  );
  const [name, setName] = useState(
    initialMode === 'KOTH' ? 'KOTH Championship Match' : 'Red vs Blue Cyber Clash'
  );

  // STEP 2: TARGET HILLS
  const [hills, setHills] = useState([
    {
      hill_id: 1,
      name: 'Hill 1 - AD Domain Controller',
      environment_type: 'ACTIVE_DIRECTORY',
      target_host: '10.0.10.10',
      target_port: 88,
      service_name: 'kerberos-dc',
    },
    {
      hill_id: 2,
      name: 'Hill 2 - Core Web Application',
      environment_type: 'WEB_APPLICATION',
      target_host: '10.0.20.10',
      target_port: 443,
      service_name: 'https-portal',
    },
    {
      hill_id: 3,
      name: 'Hill 3 - Database Cluster',
      environment_type: 'DATABASE',
      target_host: '10.0.30.10',
      target_port: 5432,
      service_name: 'postgresql',
    },
    {
      hill_id: 4,
      name: 'Hill 4 - Linux Ingress Node',
      environment_type: 'LINUX',
      target_host: '10.0.40.10',
      target_port: 22,
      service_name: 'ssh-bastion',
    },
  ]);

  const handleModeChange = (newMode) => {
    setMode(newMode);
    if (newMode === 'KOTH') {
      setFormat('SINGLE_HILL');
      if (name.includes('Red vs Blue')) setName('KOTH Championship Match');
    } else {
      setFormat('CLASSIC');
      if (name.includes('KOTH')) setName('Red vs Blue Cyber Clash');
    }
  };

  const handleSetNumHills = (num) => {
    const targetCount = Math.max(1, Math.min(10, num));
    if (targetCount === hills.length) return;

    if (targetCount < hills.length) {
      setHills(hills.slice(0, targetCount));
    } else {
      const added = [];
      const defaultTypes = [
        'LINUX',
        'WINDOWS',
        'WEB_APPLICATION',
        'DATABASE',
        'NETWORK',
        'ACTIVE_DIRECTORY',
        'CLOUD_SECURITY',
        'CONTAINER_K8S',
        'FORENSICS_IR',
      ];
      for (let i = hills.length + 1; i <= targetCount; i++) {
        const envType = defaultTypes[(i - 1) % defaultTypes.length];
        added.push({
          hill_id: i,
          name: `Hill ${i} - ${envType.replace('_', ' ')} Target`,
          environment_type: envType,
          target_host: `10.0.${i * 10}.10`,
          target_port: 80,
          service_name: `service-${i}`,
        });
      }
      setHills([...hills, ...added]);
    }
  };

  const handleAddHill = () => {
    const nextId = hills.length > 0 ? Math.max(...hills.map((h) => h.hill_id)) + 1 : 1;
    setHills([
      ...hills,
      {
        hill_id: nextId,
        name: `Hill ${nextId} - Linux Target`,
        environment_type: 'LINUX',
        target_host: `10.0.${nextId * 10}.10`,
        target_port: 80,
        service_name: `service-${nextId}`,
      },
    ]);
  };

  const handleRemoveHill = (idToRemove) => {
    if (hills.length <= 1) return;
    setHills(hills.filter((h) => h.hill_id !== idToRemove));
  };

  const handleUpdateHill = (id, field, value) => {
    setHills(
      hills.map((h) => (h.hill_id === id ? { ...h, [field]: value } : h))
    );
  };

  // STEP 4: LAUNCH COMPETITION
  const handleLaunch = async () => {
    setSubmitting(true);
    setErrorMsg('');

    // Safe backend defaults for rules and teams
    const defaultRules = {
      capture_points: 100,
      defense_points: 50,
      hold_interval_seconds: 60,
      hold_interval_points: 10,
      recapture_bonus: 25,
      penalty_points: 15,
      simulation_mode: true,
      require_authorization_gate: true,
    };

    const defaultTeams =
      mode === 'RED_VS_BLUE'
        ? [
            { team_id: 'red_team', name: 'Red Team', side: 'RED' },
            { team_id: 'blue_team', name: 'Blue Team', side: 'BLUE' },
          ]
        : [
            { team_id: 'alpha_squad', name: 'Alpha Squad', side: 'NEUTRAL' },
            { team_id: 'bravo_force', name: 'Bravo Force', side: 'NEUTRAL' },
          ];

    const formattedHills = hills.map((h, idx) => ({
      hill_id: h.hill_id,
      name: h.name || `Hill ${h.hill_id}`,
      environment_type: h.environment_type,
      target_host: h.target_host || `10.0.${h.hill_id * 10}.10`,
      target_port: parseInt(h.target_port) || 80,
      service_name: h.service_name || `svc-${h.hill_id}`,
      points_per_interval: 10,
      capture_points: 100,
      flag: `FLAG{hill_${h.hill_id}_${h.environment_type.toLowerCase()}}`,
      initial_owner_team_id:
        mode === 'RED_VS_BLUE' && idx === 0
          ? 'blue_team'
          : mode === 'RED_VS_BLUE' && idx === 1
          ? 'red_team'
          : null,
      initial_owner_side:
        mode === 'RED_VS_BLUE' && idx === 0
          ? 'BLUE'
          : mode === 'RED_VS_BLUE' && idx === 1
          ? 'RED'
          : 'NEUTRAL',
    }));

    const payload = {
      name: name.trim() || (mode === 'KOTH' ? 'KOTH Match' : 'Red vs Blue Match'),
      description: `Competition initialized via 4-step wizard. Mode: ${mode}, Format: ${format}.`,
      mode,
      format,
      duration_minutes: 60,
      rules: defaultRules,
      teams: defaultTeams,
      hills: formattedHills,
    };

    try {
      const hHeaders = headers ? headers() : { 'Content-Type': 'application/json' };
      // 1. Create competition
      const res = await fetch(`${coordinatorUrl}/api/competitions`, {
        method: 'POST',
        headers: hHeaders,
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || data.message || 'Failed to create competition');
      }

      const createdComp = data.competition;

      // 2. Start competition immediately
      await fetch(`${coordinatorUrl}/api/competition/${createdComp.competition_id}/start`, {
        method: 'POST',
        headers: hHeaders,
      });

      createdComp.status = 'ACTIVE';

      // 3. Navigate directly to correct operational workspace
      if (onCompetitionCreated) {
        onCompetitionCreated(createdComp);
      }
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const steps = [
    { num: 1, label: 'Mode & Format' },
    { num: 2, label: 'Target Hills' },
    { num: 3, label: 'Review' },
    { num: 4, label: 'Launch' },
  ];

  const currentFormats = mode === 'RED_VS_BLUE' ? RVB_FORMATS : KOTH_FORMATS;

  return (
    <div className="content-container" style={{ maxWidth: 880, margin: '0 auto', padding: '24px 20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 className="view-title" style={{ margin: 0, fontSize: 22 }}>
            Competition Creation Wizard
          </h1>
          <p className="view-subtitle" style={{ margin: '4px 0 0', fontSize: 13 }}>
            Step {currentStep} of 4: {steps[currentStep - 1].label}
          </p>
        </div>
        {onCancel && (
          <button className="btn btn-secondary btn-sm" onClick={onCancel}>
            Exit Wizard
          </button>
        )}
      </div>

      {/* Progress Bar (Exactly 4 Steps) */}
      <div className="card" style={{ padding: '12px 20px', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          {steps.map((s, idx) => {
            const isActive = currentStep === s.num;
            const isCompleted = currentStep > s.num;
            return (
              <React.Fragment key={s.num}>
                <div
                  onClick={() => {
                    if (s.num < currentStep) setCurrentStep(s.num);
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    cursor: s.num < currentStep ? 'pointer' : 'default',
                    opacity: isActive ? 1 : isCompleted ? 0.9 : 0.45,
                  }}
                >
                  <div
                    style={{
                      width: 26,
                      height: 26,
                      borderRadius: 13,
                      background: isActive
                        ? 'var(--blue-interactive)'
                        : isCompleted
                        ? 'var(--green-success)'
                        : 'var(--border-color)',
                      color: isActive || isCompleted ? '#FFFFFF' : 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: 12,
                      fontWeight: 700,
                    }}
                  >
                    {isCompleted ? <CheckCircle2 size={15} /> : s.num}
                  </div>
                  <span
                    style={{
                      fontSize: 13,
                      fontWeight: isActive ? 700 : 500,
                      color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                    }}
                  >
                    {s.num}. {s.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div
                    style={{
                      flex: 1,
                      height: 2,
                      background: isCompleted ? 'var(--green-success)' : 'var(--border-color)',
                      margin: '0 12px',
                    }}
                  />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {errorMsg && (
        <div className="alert alert-danger" style={{ marginBottom: 20 }}>
          <AlertTriangle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* =========================================================================
          STEP 1 OF 4: MODE AND FORMAT
         ========================================================================= */}
      {currentStep === 1 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Trophy size={18} />
              <span>Step 1 of 4: Select Competition Mode & Format</span>
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: 20 }}>
            <label className="form-label">Competition Name</label>
            <input
              type="text"
              className="form-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter competition name..."
            />
          </div>

          <div className="form-label" style={{ marginBottom: 10 }}>Select Competition Mode (Exactly 2 Choices)</div>
          <div className="grid-2" style={{ gap: 14, marginBottom: 24 }}>
            {/* Mode 1: KOTH */}
            <div
              className="card"
              onClick={() => handleModeChange('KOTH')}
              style={{
                cursor: 'pointer',
                padding: '16px 20px',
                border: `2px solid ${mode === 'KOTH' ? 'var(--blue-interactive)' : 'var(--border-color)'}`,
                background: mode === 'KOTH' ? 'var(--blue-bg-light)' : 'var(--panel-bg)',
                marginBottom: 0,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <Flame size={20} color={mode === 'KOTH' ? 'var(--blue-interactive)' : '#E65100'} />
                <strong style={{ fontSize: 16 }}>King of the Hill (KOTH)</strong>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
                Multi-squad territory battle. Hold hills to accumulate continuous score intervals.
              </p>
            </div>

            {/* Mode 2: Red Team vs Blue Team */}
            <div
              className="card"
              onClick={() => handleModeChange('RED_VS_BLUE')}
              style={{
                cursor: 'pointer',
                padding: '16px 20px',
                border: `2px solid ${mode === 'RED_VS_BLUE' ? 'var(--blue-interactive)' : 'var(--border-color)'}`,
                background: mode === 'RED_VS_BLUE' ? 'var(--blue-bg-light)' : 'var(--panel-bg)',
                marginBottom: 0,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <Swords size={20} color={mode === 'RED_VS_BLUE' ? 'var(--blue-interactive)' : '#2878C8'} />
                <strong style={{ fontSize: 16 }}>Red Team vs Blue Team</strong>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
                Two opposing sides in the same competition. Both sides attack, capture, defend, and recapture hills.
              </p>
            </div>
          </div>

          <div className="form-label" style={{ marginBottom: 10 }}>
            Select Format for {mode === 'RED_VS_BLUE' ? 'Red vs Blue (6 Formats)' : 'KOTH (5 Formats)'}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {currentFormats.map((fmt) => {
              const isSelected = format === fmt.id;
              return (
                <div
                  key={fmt.id}
                  onClick={() => setFormat(fmt.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 16px',
                    borderRadius: 6,
                    border: `1.5px solid ${isSelected ? 'var(--blue-interactive)' : 'var(--border-color)'}`,
                    background: isSelected ? 'var(--blue-bg-light)' : 'var(--panel-bg)',
                    cursor: 'pointer',
                  }}
                >
                  <div>
                    <strong style={{ fontSize: 14, color: 'var(--text-primary)' }}>{fmt.name}</strong>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>{fmt.desc}</div>
                  </div>
                  {isSelected ? (
                    <CheckCircle2 size={18} color="var(--blue-interactive)" />
                  ) : (
                    <div style={{ width: 18, height: 18, borderRadius: 9, border: '1.5px solid var(--border-color)' }} />
                  )}
                </div>
              );
            })}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 24 }}>
            <button className="btn btn-primary" onClick={() => setCurrentStep(2)}>
              <span>Continue to Target Hills</span>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* =========================================================================
          STEP 2 OF 4: TARGET HILLS
         ========================================================================= */}
      {currentStep === 2 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={18} />
              <span>Step 2 of 4: Configure Target Hills & Authorized Environments</span>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Quick Count:</span>
              {[1, 2, 3, 4, 6].map((cnt) => (
                <button
                  key={cnt}
                  className={`btn btn-sm ${hills.length === cnt ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '2px 8px', fontSize: 12 }}
                  onClick={() => handleSetNumHills(cnt)}
                >
                  {cnt}
                </button>
              ))}
              <button className="btn btn-secondary btn-sm" onClick={handleAddHill}>
                <Plus size={13} /> Add
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {hills.map((h, idx) => (
              <div
                key={h.hill_id}
                className="card"
                style={{ background: 'var(--bg-main)', border: '1px solid var(--border-color)', marginBottom: 0, padding: 16 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
                    <span className="badge badge-blue">Hill {idx + 1}</span>
                    <input
                      type="text"
                      className="form-input"
                      value={h.name}
                      onChange={(e) => handleUpdateHill(h.hill_id, 'name', e.target.value)}
                      placeholder="Hill Name"
                      style={{ fontWeight: 600, maxWidth: 320 }}
                    />
                  </div>

                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleRemoveHill(h.hill_id)}
                    disabled={hills.length <= 1}
                    title="Remove Hill"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>

                {/* Only Relevant Target Configuration Fields */}
                <div className="grid-3" style={{ gap: 12 }}>
                  <div className="form-group">
                    <label className="form-label">Environment Type</label>
                    <select
                      className="form-input"
                      value={h.environment_type}
                      onChange={(e) => handleUpdateHill(h.hill_id, 'environment_type', e.target.value)}
                    >
                      {HILL_ENVIRONMENT_TYPES.map((env) => (
                        <option key={env.value} value={env.value}>{env.label}</option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Target Host / IP</label>
                    <input
                      type="text"
                      className="form-input"
                      value={h.target_host}
                      onChange={(e) => handleUpdateHill(h.hill_id, 'target_host', e.target.value)}
                      placeholder="e.g. 10.0.1.10"
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Port & Service</label>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <input
                        type="number"
                        className="form-input"
                        value={h.target_port}
                        onChange={(e) => handleUpdateHill(h.hill_id, 'target_port', parseInt(e.target.value) || 80)}
                        style={{ width: 80 }}
                        title="Port"
                      />
                      <input
                        type="text"
                        className="form-input"
                        value={h.service_name}
                        onChange={(e) => handleUpdateHill(h.hill_id, 'service_name', e.target.value)}
                        placeholder="Service name"
                        title="Service Name"
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 24 }}>
            <button className="btn btn-secondary" onClick={() => setCurrentStep(1)}>
              <ChevronLeft size={16} /> Back to Mode & Format
            </button>
            <button className="btn btn-primary" onClick={() => setCurrentStep(3)}>
              <span>Continue to Review</span>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* =========================================================================
          STEP 3 OF 4: REVIEW
         ========================================================================= */}
      {currentStep === 3 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <CheckCircle2 size={18} color="var(--green-success)" />
              <span>Step 3 of 4: Review Configuration Summary</span>
            </div>
          </div>

          <div className="grid-3" style={{ marginBottom: 20 }}>
            <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>COMPETITION MODE</div>
              <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>
                {mode === 'RED_VS_BLUE' ? 'Red Team vs Blue Team' : 'King of the Hill (KOTH)'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                {mode === 'RED_VS_BLUE' ? 'Symmetric Contested Engagement' : 'Territory Domination'}
              </div>
            </div>

            <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>SELECTED FORMAT</div>
              <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>
                {currentFormats.find((f) => f.id === format)?.name || format}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                Match: {name}
              </div>
            </div>

            <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>CONTESTED HILLS</div>
              <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>
                {hills.length} Hills Configured
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                Heterogeneous Target Surface
              </div>
            </div>
          </div>

          {/* Configured Target Environments Table */}
          <div className="card" style={{ background: 'var(--panel-bg)', marginBottom: 0, padding: 0 }}>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Hill Name</th>
                    <th>Environment Type</th>
                    <th>Target Endpoint</th>
                    <th>Service</th>
                  </tr>
                </thead>
                <tbody>
                  {hills.map((h, i) => (
                    <tr key={h.hill_id}>
                      <td><strong>{i + 1}</strong></td>
                      <td><strong>{h.name}</strong></td>
                      <td>
                        <span className="badge badge-neutral">
                          {HILL_ENVIRONMENT_TYPES.find((e) => e.value === h.environment_type)?.label || h.environment_type}
                        </span>
                      </td>
                      <td><code>{h.target_host}:{h.target_port}</code></td>
                      <td><code>{h.service_name}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 24 }}>
            <button className="btn btn-secondary" onClick={() => setCurrentStep(2)}>
              <ChevronLeft size={16} /> Back to Target Hills
            </button>
            <button className="btn btn-primary" onClick={() => setCurrentStep(4)}>
              <span>Continue to Launch</span>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* =========================================================================
          STEP 4 OF 4: LAUNCH
         ========================================================================= */}
      {currentStep === 4 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Play size={18} />
              <span>Step 4 of 4: Launch Competition</span>
            </div>
          </div>

          <div
            style={{
              textAlign: 'center',
              padding: '32px 20px',
              background: 'var(--bg-main)',
              borderRadius: 8,
              marginBottom: 24,
            }}
          >
            <div
              style={{
                width: 56,
                height: 56,
                borderRadius: 28,
                background: 'var(--blue-interactive)',
                color: '#FFFFFF',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 16,
              }}
            >
              <Trophy size={28} />
            </div>

            <h2 style={{ fontSize: 20, fontWeight: 800, margin: '0 0 8px', color: 'var(--text-primary)' }}>
              Ready to Launch: {name}
            </h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto 20px' }}>
              Launching will initialize the {mode === 'RED_VS_BLUE' ? 'Red vs Blue' : 'KOTH'} match with{' '}
              {hills.length} target hills, activate authoritative server scoring, and navigate directly into the{' '}
              {mode === 'RED_VS_BLUE' ? 'Red vs Blue' : 'KOTH'} operational workspace.
            </p>

            <button
              className="btn btn-primary"
              style={{ padding: '14px 36px', fontSize: 16, fontWeight: 700 }}
              onClick={handleLaunch}
              disabled={submitting}
            >
              <Play size={18} />
              <span>{submitting ? 'Initializing Arena...' : 'Launch Competition'}</span>
            </button>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
            <button className="btn btn-secondary" onClick={() => setCurrentStep(3)} disabled={submitting}>
              <ChevronLeft size={16} /> Back to Review
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
