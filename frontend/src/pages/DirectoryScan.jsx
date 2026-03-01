import { useState } from 'react';
import { FolderSearch, Send, ShieldCheck, ShieldAlert, Loader2, Brain, FileWarning } from 'lucide-react';
import { scanDirectory } from '../api';

export default function DirectoryScan() {
  const [dirPath, setDirPath] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    if (!dirPath.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await scanDirectory(dirPath);
      setResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  const threats = result?.results?.filter(r => r.detected) || [];
  const clean = result?.results?.filter(r => !r.detected) || [];

  return (
    <div>
      <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
        <FolderSearch className="w-8 h-8 text-emerald-400" />
        Directory Scan
      </h1>
      <p className="text-gray-400 mb-8">Scan all files in a directory using Hash DB + Heuristic + AI Anomaly Detection</p>

      {/* Input */}
      <form onSubmit={handleScan} className="mb-6">
        <div className="flex gap-3">
          <input
            value={dirPath}
            onChange={(e) => setDirPath(e.target.value)}
            placeholder="Enter directory path... e.g. C:\Users\Downloads"
            className="flex-1 px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-emerald-500 focus:outline-none font-mono text-sm"
          />
          <button
            type="submit"
            disabled={loading || !dirPath.trim()}
            className="px-6 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2 py-3"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            Scan
          </button>
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">{error}</div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-4">
          {/* Summary Banner */}
          <div className={`p-6 rounded-xl border ${
            result.threats_found > 0
              ? 'bg-red-500/10 border-red-500/30'
              : 'bg-emerald-500/10 border-emerald-500/30'
          }`}>
            <div className="flex items-center gap-4">
              {result.threats_found > 0 ? (
                <ShieldAlert className="w-12 h-12 text-red-400" />
              ) : (
                <ShieldCheck className="w-12 h-12 text-emerald-400" />
              )}
              <div>
                <h2 className={`text-2xl font-bold ${result.threats_found > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {result.threats_found > 0
                    ? `⚠️ ${result.threats_found} Threat${result.threats_found > 1 ? 's' : ''} Found`
                    : '✅ Directory Clean'}
                </h2>
                <p className="text-gray-400 text-sm mt-1">
                  Scanned {result.files_scanned} files in {result.scan_time}s
                </p>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Files Scanned" value={result.files_scanned} color="text-blue-400" />
            <StatCard label="Threats Found" value={result.threats_found} color={result.threats_found > 0 ? 'text-red-400' : 'text-emerald-400'} />
            <StatCard label="Clean Files" value={result.files_scanned - result.threats_found} color="text-emerald-400" />
            <StatCard label="Scan Time" value={`${result.scan_time}s`} color="text-amber-400" />
          </div>

          {/* Threats List */}
          {threats.length > 0 && (
            <div className="bg-gray-900 border border-red-500/30 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-red-400 uppercase mb-3 flex items-center gap-2">
                <FileWarning className="w-4 h-4" />
                Detected Threats ({threats.length})
              </h3>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {threats.map((file, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-red-500/10 rounded-lg">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white font-medium truncate">{file.filename}</p>
                      <p className="text-xs text-gray-500 truncate">{file.path}</p>
                    </div>
                    <div className="flex items-center gap-3 ml-3 flex-shrink-0">
                      <span className="text-xs text-gray-400">{formatBytes(file.file_size)}</span>
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                        { critical: 'bg-red-500/20 text-red-400',
                          high: 'bg-orange-500/20 text-orange-400',
                          medium: 'bg-amber-500/20 text-amber-400',
                        }[file.threat_level] || 'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {file.threat_level?.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-500">{file.method}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Clean Files (collapsed) */}
          {clean.length > 0 && (
            <details className="bg-gray-900 border border-gray-800 rounded-xl">
              <summary className="p-5 cursor-pointer text-sm font-semibold text-gray-400 uppercase hover:text-white transition-colors">
                Clean Files ({clean.length}) — Click to expand
              </summary>
              <div className="px-5 pb-5 space-y-1 max-h-64 overflow-y-auto">
                {clean.map((file, i) => (
                  <div key={i} className="flex items-center justify-between p-2 bg-gray-800/50 rounded text-xs">
                    <span className="text-gray-300 truncate flex-1">{file.filename}</span>
                    <span className="text-gray-500 ml-3">{formatBytes(file.file_size)}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-gray-500 mt-1">{label}</p>
    </div>
  );
}
