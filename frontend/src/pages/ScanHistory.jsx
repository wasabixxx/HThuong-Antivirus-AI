import { useState, useEffect } from 'react';
import { History, ShieldAlert, ShieldCheck, Globe, FileSearch, ShieldX, Trash2, RefreshCw, Download, Filter } from 'lucide-react';
import { getHistory, clearHistory } from '../api';

export default function ScanHistory() {
  const [history, setHistory] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Advanced filters
  const [filterDetected, setFilterDetected] = useState('all');    // all, threats, clean
  const [filterType, setFilterType] = useState('all');             // all, file, url, waf
  const [filterLevel, setFilterLevel] = useState('all');           // all, safe, low, medium, high, critical
  const [filterMethod, setFilterMethod] = useState('all');         // all, hash_local, virustotal, heuristic, anomaly_detection, waf
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    loadHistory();
  }, []);

  async function loadHistory() {
    setLoading(true);
    try {
      const res = await getHistory(200);
      setHistory(res.items || []);
      setTotal(res.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function handleClear() {
    if (!confirm('Clear all scan history?')) return;
    try {
      await clearHistory();
      setHistory([]);
      setTotal(0);
    } catch (e) {
      console.error(e);
    }
  }

  function handleExport(format) {
    const data = filtered;
    if (data.length === 0) return;

    let content, filename, mimeType;

    if (format === 'json') {
      content = JSON.stringify(data, null, 2);
      filename = `scan_history_${new Date().toISOString().slice(0, 10)}.json`;
      mimeType = 'application/json';
    } else {
      // CSV
      const headers = ['timestamp', 'type', 'detected', 'threat_level', 'method', 'scan_time', 'filename', 'url', 'attacks'];
      const rows = data.map(item => headers.map(h => {
        const val = item[h];
        if (Array.isArray(val)) return val.join('; ');
        if (val === undefined || val === null) return '';
        return String(val);
      }));
      content = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
      filename = `scan_history_${new Date().toISOString().slice(0, 10)}.csv`;
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  const filtered = history.filter(item => {
    if (filterDetected === 'threats' && !item.detected) return false;
    if (filterDetected === 'clean' && item.detected) return false;
    if (filterType !== 'all' && item.type !== filterType) return false;
    if (filterLevel !== 'all' && item.threat_level !== filterLevel) return false;
    if (filterMethod !== 'all' && item.method !== filterMethod) return false;
    return true;
  });

  // Collect unique values for filter dropdowns
  const uniqueTypes = [...new Set(history.map(i => i.type))].filter(Boolean);
  const uniqueLevels = [...new Set(history.map(i => i.threat_level))].filter(Boolean);
  const uniqueMethods = [...new Set(history.map(i => i.method))].filter(Boolean);

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
      return d.toLocaleString('vi-VN', {
        month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
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
          <p className="text-gray-400 mt-1">
            Total: {total} scans · Showing: {filtered.length}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => handleExport('csv')} title="Export CSV"
            className="p-2 text-gray-400 hover:text-emerald-400 transition-colors" disabled={filtered.length === 0}>
            <Download className="w-5 h-5" />
          </button>
          <button onClick={handleClear} title="Clear history"
            className="p-2 text-gray-400 hover:text-red-400 transition-colors">
            <Trash2 className="w-5 h-5" />
          </button>
          <button onClick={loadHistory} title="Refresh"
            className="p-2 text-gray-400 hover:text-white transition-colors">
            <RefreshCw className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Quick Filters */}
      <div className="flex gap-2 mb-4 flex-wrap items-center">
        {[
          { id: 'all', label: 'All' },
          { id: 'threats', label: 'Threats Only' },
          { id: 'clean', label: 'Clean Only' },
        ].map(f => (
          <button key={f.id}
            onClick={() => setFilterDetected(f.id)}
            className={`px-4 py-2 text-sm rounded-lg transition-colors ${
              filterDetected === f.id
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-gray-800 text-gray-400 hover:text-white border border-gray-700'
            }`}
          >
            {f.label}
          </button>
        ))}

        <div className="ml-auto">
          <button onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-1.5 px-3 py-2 text-sm rounded-lg transition-colors ${
              showFilters ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'bg-gray-800 text-gray-400 hover:text-white border border-gray-700'
            }`}
          >
            <Filter className="w-4 h-4" />
            Advanced
          </button>
        </div>
      </div>

      {/* Advanced Filters Panel */}
      {showFilters && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4 grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Type filter */}
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Scan Type</label>
            <select value={filterType} onChange={e => setFilterType(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500">
              <option value="all">All Types</option>
              {uniqueTypes.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
          </div>
          {/* Threat Level filter */}
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Threat Level</label>
            <select value={filterLevel} onChange={e => setFilterLevel(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500">
              <option value="all">All Levels</option>
              {uniqueLevels.map(l => <option key={l} value={l}>{l.toUpperCase()}</option>)}
            </select>
          </div>
          {/* Method filter */}
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Detection Method</label>
            <select value={filterMethod} onChange={e => setFilterMethod(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500">
              <option value="all">All Methods</option>
              {uniqueMethods.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
        </div>
      )}

      {/* Export Buttons */}
      {filtered.length > 0 && (
        <div className="flex gap-2 mb-4">
          <button onClick={() => handleExport('csv')}
            className="text-xs px-3 py-1.5 bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors flex items-center gap-1">
            <Download className="w-3 h-3" /> Export CSV
          </button>
          <button onClick={() => handleExport('json')}
            className="text-xs px-3 py-1.5 bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors flex items-center gap-1">
            <Download className="w-3 h-3" /> Export JSON
          </button>
          <span className="text-xs text-gray-600 self-center ml-2">
            {filtered.length} records
          </span>
        </div>
      )}

      {/* List */}
      {loading ? (
        <div className="text-center text-gray-500 py-12">Loading...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center text-gray-500 py-12">
          <History className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No scan history matching filters.</p>
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
