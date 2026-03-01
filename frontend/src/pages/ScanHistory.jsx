import { useState, useEffect } from 'react';
import { History, ShieldAlert, ShieldCheck, Globe, FileSearch, ShieldX, Trash2, RefreshCw } from 'lucide-react';
import { getHistory } from '../api';

export default function ScanHistory() {
  const [history, setHistory] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, threats, clean

  useEffect(() => {
    loadHistory();
  }, []);

  async function loadHistory() {
    setLoading(true);
    try {
      const res = await getHistory(100);
      setHistory(res.items || []);
      setTotal(res.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  const filtered = history.filter(item => {
    if (filter === 'threats') return item.detected;
    if (filter === 'clean') return !item.detected;
    return true;
  });

  function typeIcon(type) {
    switch (type) {
      case 'file': return <FileSearch className="w-4 h-4" />;
      case 'url': return <Globe className="w-4 h-4" />;
      case 'waf': return <ShieldX className="w-4 h-4" />;
      default: return <ShieldAlert className="w-4 h-4" />;
    }
  }

  function threatColor(level) {
    const colors = {
      safe: 'text-emerald-400',
      low: 'text-yellow-400',
      medium: 'text-amber-400',
      high: 'text-orange-400',
      critical: 'text-red-400',
      unknown: 'text-gray-400',
    };
    return colors[level] || 'text-gray-400';
  }

  function formatTime(ts) {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <History className="w-8 h-8 text-emerald-400" />
            Scan History
          </h1>
          <p className="text-gray-400 mt-1">Total: {total} scans recorded</p>
        </div>
        <button onClick={loadHistory} className="p-2 text-gray-400 hover:text-white transition-colors">
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-6">
        {[
          { id: 'all', label: 'All' },
          { id: 'threats', label: 'Threats Only' },
          { id: 'clean', label: 'Clean Only' },
        ].map(f => (
          <button key={f.id}
            onClick={() => setFilter(f.id)}
            className={`px-4 py-2 text-sm rounded-lg transition-colors ${
              filter === f.id
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-gray-800 text-gray-400 hover:text-white border border-gray-700'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="text-center text-gray-500 py-12">Loading...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center text-gray-500 py-12">
          <History className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No scan history yet. Start scanning!</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((item, i) => (
            <div key={i} className={`flex items-center gap-4 p-4 rounded-lg border transition-colors ${
              item.detected ? 'bg-red-500/5 border-red-500/20' : 'bg-gray-900 border-gray-800'
            }`}>
              {/* Icon */}
              <div className={`p-2 rounded-lg ${
                item.detected ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                {typeIcon(item.type)}
              </div>

              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white truncate">
                    {item.filename || item.url || item.type?.toUpperCase()}
                  </span>
                  <span className="text-xs px-1.5 py-0.5 bg-gray-800 text-gray-400 rounded">
                    {item.type}
                  </span>
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                  <span>{formatTime(item.timestamp)}</span>
                  <span>{item.method}</span>
                  {item.scan_time && <span>{item.scan_time}s</span>}
                  {item.file_size && <span>{(item.file_size / 1024).toFixed(1)} KB</span>}
                  {item.attacks && item.attacks.length > 0 && (
                    <span className="text-red-400">{item.attacks.join(', ')}</span>
                  )}
                </div>
              </div>

              {/* Status */}
              <span className={`text-xs font-medium ${threatColor(item.threat_level)}`}>
                {item.threat_level?.toUpperCase()}
              </span>
              <span className={`text-xs px-2 py-1 rounded ${
                item.detected ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                {item.detected ? (item.action || 'THREAT') : (item.action || 'CLEAN')}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
