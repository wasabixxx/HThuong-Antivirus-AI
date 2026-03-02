import { useState, useRef, useEffect } from 'react';
import { FileSearch, Upload, Shield, ShieldAlert, ShieldCheck, ExternalLink, Loader2, Brain, CheckCircle2, Circle, TestTube2, FileDown } from 'lucide-react';
import { scanFile, downloadEicar } from '../api';
import { exportFileScanPDF } from '../pdfExport';

const SCAN_LAYERS = [
  { id: 'hash', name: 'Tầng 1: CSDL Hash cục bộ', desc: 'Tra cứu SHA-256 trong ~39.000 chữ ký', time: 300 },
  { id: 'vt', name: 'Tầng 2: VirusTotal API', desc: 'Kiểm tra bằng 70+ engine AV (đám mây)', time: 2000 },
  { id: 'heuristic', name: 'Tầng 3: Phân tích Heuristic', desc: 'Entropy + mẫu đáng ngờ + tiêu đề PE', time: 500 },
  { id: 'anomaly', name: 'Tầng 4: Phát hiện bất thường AI', desc: 'Mô hình ML Isolation Forest', time: 400 },
];

export default function FileScan() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState(null);
  const [activeLayer, setActiveLayer] = useState(-1);
  const fileRef = useRef();
  const timerRef = useRef(null);

  // Animate through layers during scan
  useEffect(() => {
    if (loading) {
      setActiveLayer(0);
      let layer = 0;
      const advanceLayer = () => {
        layer++;
        if (layer < SCAN_LAYERS.length) {
          setActiveLayer(layer);
          timerRef.current = setTimeout(advanceLayer, SCAN_LAYERS[layer].time);
        }
      };
      timerRef.current = setTimeout(advanceLayer, SCAN_LAYERS[0].time);
    } else {
      setActiveLayer(-1);
      if (timerRef.current) clearTimeout(timerRef.current);
    }
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [loading]);

  async function handleScan(file) {
    if (!file) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await scanFile(file);
      setResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleScan(file);
  }

  function handleFileChange(e) {
    const file = e.target.files[0];
    if (file) handleScan(file);
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  return (
    <div>
      <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
        <FileSearch className="w-8 h-8 text-emerald-400" />
        Quét tệp tin
      </h1>
      <p className="text-gray-400 mb-8">Tải tệp lên để quét qua 4 tầng phát hiện AI</p>

      {/* Upload Zone */}
      <div
        className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${
          dragOver ? 'border-emerald-400 bg-emerald-500/10' : 'border-gray-700 hover:border-gray-500 bg-gray-900'
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input ref={fileRef} type="file" className="hidden" onChange={handleFileChange} />
        {loading ? (
          <div className="flex flex-col items-center gap-4 w-full max-w-md mx-auto">
            <Loader2 className="w-10 h-10 text-emerald-400 animate-spin" />
            <p className="text-emerald-400 font-medium">Đang quét qua 4 tầng AI...</p>
            <div className="w-full space-y-2">
              {SCAN_LAYERS.map((layer, idx) => {
                const isDone = idx < activeLayer;
                const isActive = idx === activeLayer;
                const isPending = idx > activeLayer;
                return (
                  <div key={layer.id}
                    className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm transition-all duration-300 ${
                      isActive ? 'bg-emerald-500/15 border border-emerald-500/30' :
                      isDone ? 'bg-gray-800/50 opacity-60' : 'bg-gray-800/30 opacity-40'
                    }`}
                  >
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : isActive ? (
                      <Loader2 className="w-4 h-4 text-emerald-400 animate-spin flex-shrink-0" />
                    ) : (
                      <Circle className="w-4 h-4 text-gray-600 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className={`font-medium ${isActive ? 'text-emerald-300' : isDone ? 'text-gray-400' : 'text-gray-600'}`}>
                        {layer.name}
                      </p>
                      <p className="text-xs text-gray-500 truncate">{layer.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <Upload className="w-12 h-12 text-gray-400" />
            <p className="text-gray-300 font-medium">Kéo thả tệp vào đây hoặc nhấp để chọn</p>
            <p className="text-gray-500 text-sm">Hỗ trợ mọi loại tệp • Tối đa 32MB cho VirusTotal</p>
          </div>
        )}
      </div>

      {/* EICAR Test Button */}
      <div className="mt-4 flex items-center gap-3">
        <button
          onClick={async () => {
            try {
              const blob = await downloadEicar();
              const file = new File([blob], 'eicar_test_file.txt', { type: 'application/octet-stream' });
              handleScan(file);
            } catch (e) {
              setError('Failed to download EICAR test file: ' + e.message);
            }
          }}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-lg hover:bg-amber-500/20 transition-colors text-sm disabled:opacity-50"
        >
          <TestTube2 className="w-4 h-4" />
          Thử với tệp EICAR
        </button>
        <span className="text-gray-500 text-xs">Tệp kiểm tra antivirus chuẩn — KHÔNG phải virus thật</span>
      </div>

      {/* Error */}
      {error && (
        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="mt-6 space-y-4">
          {/* Status Banner */}
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
                  {result.detected ? '⚠️ PHÁT HIỆN MỐI ĐE DỌA' : '✅ AN TOÀN — Không phát hiện mối đe dọa'}
                </h2>
                <p className="text-gray-300 mt-1">{result.message}</p>
              </div>
            </div>
          </div>

          {/* Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* File Info */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Thông tin tệp</h3>
              <div className="space-y-2 text-sm">
                <Row label="Tên tệp" value={result.filename} />
                <Row label="Kích thước" value={formatBytes(result.file_size)} />
                <Row label="Thời gian quét" value={`${result.scan_time}s`} />
                <Row label="Phương thức" value={result.method} />
              </div>
            </div>

            {/* Threat Info */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Phân tích mối đe dọa</h3>
              <div className="space-y-2 text-sm">
                <Row label="Mức độ đe dọa" value={
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    { safe: 'bg-emerald-500/20 text-emerald-400',
                      low: 'bg-yellow-500/20 text-yellow-400',
                      medium: 'bg-amber-500/20 text-amber-400',
                      high: 'bg-orange-500/20 text-orange-400',
                      critical: 'bg-red-500/20 text-red-400',
                      unknown: 'bg-gray-500/20 text-gray-400',
                    }[result.threat_level] || ''
                  }`}>
                    {result.threat_level?.toUpperCase()}
                  </span>
                } />
                <Row label="Độ tin cậy" value={`${((result.confidence || 0) * 100).toFixed(1)}%`} />
                {result.threat_name && <Row label="Tên mối đe dọa" value={result.threat_name} />}
                {result.vt_link && (
                  <Row label="VirusTotal" value={
                    <a href={result.vt_link} target="_blank" rel="noopener noreferrer"
                       className="text-blue-400 hover:underline flex items-center gap-1">
                      Xem báo cáo <ExternalLink className="w-3 h-3" />
                    </a>
                  } />
                )}
              </div>
            </div>
          </div>

          {/* VT Stats */}
          {result.vt_stats && result.vt_stats.total > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Kết quả VirusTotal</h3>
              <div className="flex gap-6 flex-wrap">
                <VTStat label="Độc hại" value={result.vt_stats.malicious} color="text-red-400" />
                <VTStat label="Đáng ngờ" value={result.vt_stats.suspicious} color="text-amber-400" />
                <VTStat label="Không phát hiện" value={result.vt_stats.undetected} color="text-green-400" />
                <VTStat label="Tổng engine" value={result.vt_stats.total} color="text-blue-400" />
              </div>
              {/* Progress bar */}
              <div className="mt-3 h-2 bg-gray-800 rounded-full overflow-hidden flex">
                {result.vt_stats.malicious > 0 && (
                  <div className="bg-red-500 h-full" style={{ width: `${(result.vt_stats.malicious / result.vt_stats.total) * 100}%` }} />
                )}
                {result.vt_stats.suspicious > 0 && (
                  <div className="bg-amber-500 h-full" style={{ width: `${(result.vt_stats.suspicious / result.vt_stats.total) * 100}%` }} />
                )}
                <div className="bg-emerald-500 h-full flex-1" />
              </div>
            </div>
          )}

          {/* Layer Details */}
          {result.layers && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Phân tích từng tầng</h3>
              <div className="space-y-3">
                {result.layers.hash_local && (
                  <LayerRow name="Tầng 1: CSDL Hash cục bộ" result={result.layers.hash_local} />
                )}
                {result.layers.virustotal && (
                  <LayerRow name="Tầng 2: VirusTotal" result={result.layers.virustotal} />
                )}
                {result.layers.heuristic && (
                  <LayerRow name="Tầng 3: Heuristic" result={result.layers.heuristic} />
                )}
                {result.layers.anomaly_detection && (
                  <LayerRow name="Tầng 4: Phát hiện bất thường AI" result={result.layers.anomaly_detection} />
                )}
              </div>
            </div>
          )}

          {/* Anomaly Detection Details */}
          {result.layers?.anomaly_detection?.features && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-5 h-5 text-purple-400" />
                <h3 className="text-sm font-semibold text-white uppercase">Phân tích bất thường AI (Isolation Forest)</h3>
                <span className={`text-xs px-2 py-0.5 rounded ml-auto ${result.layers.anomaly_detection.detected ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                  {result.layers.anomaly_detection.prediction?.toUpperCase()}
                </span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                <FeatureCard label="Entropy" value={result.layers.anomaly_detection.features.entropy?.toFixed(2)} warn={result.layers.anomaly_detection.features.entropy > 7.0} />
                <FeatureCard label="Mẫu đáng ngờ" value={result.layers.anomaly_detection.features.suspicious_patterns} warn={result.layers.anomaly_detection.features.suspicious_patterns > 3} />
                <FeatureCard label="Mẫu mạng" value={result.layers.anomaly_detection.features.network_patterns} warn={result.layers.anomaly_detection.features.network_patterns > 3} />
                <FeatureCard label="Điểm bất thường" value={result.layers.anomaly_detection.anomaly_score?.toFixed(3)} warn={result.layers.anomaly_detection.anomaly_score < 0} />
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <FeatureCard label="Là PE" value={result.layers.anomaly_detection.features.is_pe ? 'Có' : 'Không'} />
                <FeatureCard label="Tỉ lệ byte null" value={(result.layers.anomaly_detection.features.null_byte_ratio * 100).toFixed(1) + '%'} />
                <FeatureCard label="Tỉ lệ in được" value={(result.layers.anomaly_detection.features.printable_ratio * 100).toFixed(1) + '%'} />
                <FeatureCard label="Byte độc nhất" value={result.layers.anomaly_detection.features.unique_bytes} />
              </div>
            </div>
          )}

          {/* Export PDF Button */}
          <div className="flex justify-end">
            <button
              onClick={() => exportFileScanPDF(result)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600/20 border border-blue-500/30 text-blue-400 rounded-lg hover:bg-blue-600/30 transition-colors text-sm"
            >
              <FileDown className="w-4 h-4" />
              Xuất báo cáo PDF
            </button>
          </div>

          {/* Heuristic Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Lý do Heuristic</h3>
              <ul className="space-y-1">
                {result.reasons.map((r, i) => (
                  <li key={i} className="text-sm text-amber-300 flex items-start gap-2">
                    <span className="text-amber-500 mt-0.5">⚠</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-200">{value}</span>
    </div>
  );
}

function VTStat({ label, value, color }) {
  return (
    <div className="text-center">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

function LayerRow({ name, result }) {
  const detected = result.detected;
  return (
    <div className={`flex items-center justify-between p-3 rounded-lg ${
      detected ? 'bg-red-500/10' : 'bg-gray-800/50'
    }`}>
      <span className="text-sm text-gray-300">{name}</span>
      <span className={`text-xs px-2 py-1 rounded font-medium ${
        detected
          ? 'bg-red-500/20 text-red-400'
          : result.error
            ? 'bg-gray-500/20 text-gray-400'
            : 'bg-emerald-500/20 text-emerald-400'
      }`}>
        {detected ? 'PHÁT HIỆN' : result.error ? 'LỖI' : result.message === 'Not found in VirusTotal database' ? 'KHÔNG CÓ TRONG DB' : 'AN TOÀN'}
      </span>
    </div>
  );
}

function FeatureCard({ label, value, warn }) {
  return (
    <div className={`bg-gray-800 rounded-lg p-2.5 ${warn ? 'ring-1 ring-amber-500/30' : ''}`}>
      <p className="text-xs text-gray-500">{label}</p>
      <p className={`text-sm font-semibold ${warn ? 'text-amber-400' : 'text-gray-200'}`}>{value}</p>
    </div>
  );
}
