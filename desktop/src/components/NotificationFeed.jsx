import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Bell,
  BellOff,
  Filter,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Shield,
  ListTodo,
  Users,
  Lock,
  Radio,
  Search,
  ExternalLink,
  Info,
  Clock,
  Sparkles,
} from 'lucide-react';

export default function NotificationFeed({ coordinatorUrl, headers, teamId, competitionId }) {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isMuted, setIsMuted] = useState(() => localStorage.getItem('koth_notif_muted') === 'true');
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const categories = [
    { id: 'ALL', label: 'All Events' },
    { id: 'HILLS', label: 'Hills & Portals' },
    { id: 'TASKS', label: 'Swarm Tasks' },
    { id: 'AGENTS', label: 'Agent Health' },
    { id: 'SECURITY', label: 'Security & Gates' },
    { id: 'COORDINATION', label: 'Coordination' },
  ];

  const fetchNotifications = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (selectedCategory && selectedCategory !== 'ALL') {
        params.append('category', selectedCategory);
      }
      if (teamId) params.append('team_id', teamId);
      if (competitionId) params.append('competition_id', competitionId);
      params.append('limit', '80');

      const res = await fetch(`${coordinatorUrl}/api/swarm/notifications?${params.toString()}`, {
        headers: headers ? headers() : {},
      });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.notifications || []);
        setLastRefreshed(new Date());
      }
    } catch (e) {
      console.warn('Failed to fetch notifications:', e);
    } finally {
      setLoading(false);
    }
  }, [coordinatorUrl, headers, selectedCategory, teamId, competitionId]);

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 3000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  const toggleMute = () => {
    const next = !isMuted;
    setIsMuted(next);
    localStorage.setItem('koth_notif_muted', String(next));
  };

  const filteredNotifications = useMemo(() => {
    return notifications.filter((notif) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const title = (notif.title || '').toLowerCase();
        const desc = (notif.description || '').toLowerCase();
        const aid = (notif.agent_id || '').toLowerCase();
        const etype = (notif.event_type || '').toLowerCase();
        if (!title.includes(q) && !desc.includes(q) && !aid.includes(q) && !etype.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [notifications, searchQuery]);

  const getSeverityBadge = (severity) => {
    const s = (severity || 'INFO').toUpperCase();
    if (s === 'SUCCESS') return 'badge-green';
    if (s === 'CRITICAL' || s === 'ERROR') return 'badge-red';
    if (s === 'WARNING') return 'badge-amber';
    return 'badge-blue';
  };

  const getEventIcon = (category, severity) => {
    const s = (severity || 'INFO').toUpperCase();
    if (s === 'CRITICAL' || s === 'ERROR') return <AlertTriangle size={15} color="#DC2626" />;
    if (s === 'SUCCESS') return <CheckCircle size={15} color="#16A34A" />;
    if (category === 'HILLS') return <Shield size={15} color="#2878C8" />;
    if (category === 'TASKS') return <ListTodo size={15} color="#0284C7" />;
    if (category === 'AGENTS') return <Users size={15} color="#6366F1" />;
    if (category === 'SECURITY') return <Lock size={15} color="#DC2626" />;
    return <Radio size={15} color="#2878C8" />;
  };

  return (
    <div className="content-container" style={{ paddingBottom: 40 }}>
      {/* Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Live Competition Event Feed</h1>
          <p className="view-subtitle">
            Authoritative real-time feed of hill captures, verification checks, task lifecycle events, and security notices
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            onClick={toggleMute}
            className={`btn ${isMuted ? 'btn-secondary' : 'btn-outline'}`}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, height: 36 }}
            title={isMuted ? 'Unmute notification alerts' : 'Mute notification alerts'}
          >
            {isMuted ? <BellOff size={15} /> : <Bell size={15} color="#2878C8" />}
            <span>{isMuted ? 'Muted' : 'Sound Alerts On'}</span>
          </button>
          <button
            onClick={fetchNotifications}
            className="btn btn-outline"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, height: 36 }}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Control Bar: Categories & Search */}
      <div
        className="card"
        style={{
          marginBottom: 16,
          padding: '12px 16px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        {/* Category Pills */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {categories.map((cat) => {
            const active = selectedCategory === cat.id;
            return (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                style={{
                  border: active ? '1px solid #2878C8' : '1px solid #E2E8F0',
                  background: active ? '#EAF3FF' : '#FFFFFF',
                  color: active ? '#2878C8' : '#64748B',
                  fontWeight: active ? 600 : 500,
                  fontSize: 12,
                  padding: '5px 12px',
                  borderRadius: 6,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {cat.label}
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', width: 260 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: '#94A3B8' }} />
          <input
            type="text"
            className="form-control"
            placeholder="Search events, agents, hills..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              paddingLeft: 32,
              height: 34,
              fontSize: 12,
              borderRadius: 6,
            }}
          />
        </div>
      </div>

      {/* Event Stream List */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            padding: '12px 18px',
            borderBottom: '1px solid #E2E8F0',
            background: '#F8FAFC',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span style={{ fontSize: 13, fontWeight: 600, color: '#172536' }}>
            Event Stream ({filteredNotifications.length} items)
          </span>
          <span style={{ fontSize: 11, color: '#64748B' }}>
            Auto-syncing · Last updated: {lastRefreshed.toLocaleTimeString()}
          </span>
        </div>

        {filteredNotifications.length === 0 ? (
          <div style={{ padding: '48px 20px', textAlign: 'center', color: '#94A3B8' }}>
            <Radio size={36} style={{ margin: '0 auto 12px auto', opacity: 0.5, display: 'block' }} />
            <div style={{ fontSize: 14, fontWeight: 500, color: '#64748B' }}>No events recorded yet</div>
            <div style={{ fontSize: 12, marginTop: 4 }}>
              Events will appear in real time as agents capture hills, run tasks, or encounter security gates.
            </div>
          </div>
        ) : (
          <div style={{ maxHeight: 600, overflowY: 'auto' }}>
            {filteredNotifications.map((notif, index) => {
              const dt = notif.timestamp ? new Date(notif.timestamp * 1000) : new Date();
              const badgeClass = getSeverityBadge(notif.severity);

              return (
                <div
                  key={notif.event_id || index}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 14,
                    padding: '12px 18px',
                    borderBottom: '1px solid #F1F5F9',
                    background: index % 2 === 0 ? '#FFFFFF' : '#FAFCFF',
                    transition: 'background 0.1s ease',
                  }}
                >
                  {/* Icon Indicator */}
                  <div
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: 8,
                      background: '#F1F5F9',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      marginTop: 2,
                    }}
                  >
                    {getEventIcon(notif.category, notif.severity)}
                  </div>

                  {/* Body */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 13, fontWeight: 600, color: '#172536' }}>
                        {notif.title || notif.event_type}
                      </span>
                      <span className={`badge ${badgeClass}`} style={{ fontSize: 10, padding: '2px 7px' }}>
                        {notif.severity || 'INFO'}
                      </span>
                      <span className="badge badge-neutral" style={{ fontSize: 10, padding: '2px 7px' }}>
                        {notif.category || 'GENERAL'}
                      </span>
                      {notif.agent_id && (
                        <span
                          className="badge"
                          style={{
                            fontSize: 10,
                            padding: '2px 7px',
                            background: '#EFF6FF',
                            color: '#1D4ED8',
                            border: '1px solid #BFDBFE',
                          }}
                        >
                          {notif.agent_id}
                        </span>
                      )}
                      {notif.hill_id != null && (
                        <span
                          className="badge"
                          style={{
                            fontSize: 10,
                            padding: '2px 7px',
                            background: '#FEF3C7',
                            color: '#B45309',
                            border: '1px solid #FDE68A',
                          }}
                        >
                          Hill {notif.hill_id}
                        </span>
                      )}
                    </div>

                    <div style={{ fontSize: 12, color: '#475569', marginTop: 4, lineHeight: 1.4 }}>
                      {notif.description}
                    </div>

                    {notif.details && Object.keys(notif.details).length > 0 && (
                      <div
                        style={{
                          fontSize: 11,
                          color: '#64748B',
                          marginTop: 6,
                          background: '#F8FAFC',
                          padding: '4px 8px',
                          borderRadius: 4,
                          display: 'inline-block',
                          fontFamily: 'monospace',
                        }}
                      >
                        {JSON.stringify(notif.details).slice(0, 140)}
                        {JSON.stringify(notif.details).length > 140 ? '...' : ''}
                      </div>
                    )}
                  </div>

                  {/* Timestamp */}
                  <div
                    style={{
                      fontSize: 11,
                      color: '#94A3B8',
                      whiteSpace: 'nowrap',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4,
                      flexShrink: 0,
                    }}
                  >
                    <Clock size={11} />
                    <span>{dt.toLocaleTimeString()}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

