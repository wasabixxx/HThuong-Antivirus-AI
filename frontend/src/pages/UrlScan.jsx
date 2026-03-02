import { useState } from 'react';
import { Globe, Search, ShieldAlert, ShieldCheck, ExternalLink, Loader2, FileDown } from 'lucide-react';
import { scanUrl } from '../api';
import { exportUrlScanPDF } from '../pdfExport';

export default function UrlScan() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;

    // Validate URL format
    if (!/^https?:\/\/.+/i.test(trimmed)) {
      setError('URL phải bắt đầu bằng http:// hoặc https://');
      return;
    }
    try { new URL(trimmed); } catch {
      setError('URL không hợp lệ. Ví dụ: https://example.com');
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await scanUrl(url.trim());
      setResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
        <Globe className="w-8 h-8 text-emerald-400" />
        Quét URL
      </h1>
      <p className="text-gray-400 mb-8">Kiểm tra URL phát hiện lừa đảo, mã độc và các mối đe dọa khác qua VirusTotal</p>

      {/* Input */}
      <form onSubmit={handleScan} className="flex gap-3 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com hoặc trang-đáng-ngờ.xyz"
            className="w-full pl-12 pr-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          Quét
        </button>
      </form>

      {/* Example URLs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        <span className="text-xs text-gray-500">Thử:</span>
        {['https://google.com', 'https://github.com', 'http://malware.testing.google.test/testing/malware/'].map(u => (
          <button key={u} onClick={() => setUrl(u)}
                  className="text-xs px-2 py-1 bg-gray-800 text-gray-400 hover:text-white rounded transition-colors">
            {u.length > 40 ? u.slice(0, 40) + '...' : u}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-4">
          {/* Status */}
          <div className={`p-6 rounded-xl border ${
            result.detected
              ? 'bg-red-500/10 border-red-500/30'
              : 'bg-emerald-500/10 border-emerald-500/30'
          }`}>
            <div className="flex items-center gap-4">
              {result.detected ? (
                <ShieldAlert className="w-12 h-12 text-red-400" />
              ) : (
                <ShieldCheck className="w-12 h-12 text-emerald-400" />
              )}
              <div>
                <h2 className={`text-2xl font-bold ${result.detected ? 'text-red-400' : 'text-emerald-400'}`}>
                  {result.detected ? '⚠️ URL NGUY HIỂM' : '✅ URL an toàn'}
                </h2>
                <p className="text-gray-300 mt-1 break-all">{result.url}</p>
              </div>
            </div>
          </div>

          {/* Stats */}
          {result.stats && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Phân tích VirusTotal</h3>
              <div className="flex gap-8">
                <div className="text-center">
                  <p className="text-3xl font-bold text-red-400">{result.stats.malicious}</p>
                  <p className="text-xs text-gray-500">Độc hại</p>
                </div>
                <div className="text-center">
                  <p className="text-3xl font-bold text-amber-400">{result.stats.suspicious}</p>
                  <p className="text-xs text-gray-500">Đáng ngờ</p>
                </div>
                <div className="text-center">
                  <p className="text-3xl font-bold text-emerald-400">{result.stats.harmless}</p>
                  <p className="text-xs text-gray-500">An toàn</p>
                </div>
                <div className="text-center">
                  <p className="text-3xl font-bold text-blue-400">{result.stats.total}</p>
                  <p className="text-xs text-gray-500">Tổng</p>
                </div>
              </div>
              {result.vt_link && (
                <a href={result.vt_link} target="_blank" rel="noopener noreferrer"
                   className="mt-4 inline-flex items-center gap-1 text-sm text-blue-400 hover:underline">
                  Xem báo cáo đầy đủ trên VirusTotal <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          )}

          {/* Export PDF */}
          <div className="flex justify-end">
            <button
              onClick={() => exportUrlScanPDF(result)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600/20 border border-blue-500/30 text-blue-400 rounded-lg hover:bg-blue-600/30 transition-colors text-sm"
            >
              <FileDown className="w-4 h-4" />
              Xuất báo cáo PDF
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
