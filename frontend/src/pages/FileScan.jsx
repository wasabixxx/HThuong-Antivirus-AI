import { useState, useRef, useEffect } from 'react';
import { FileSearch, Upload, Shield, ShieldAlert, ShieldCheck, ExternalLink, Loader2, Brain, CheckCircle2, Circle, TestTube2 } from 'lucide-react';
import { scanFile, downloadEicar } from '../api';

const SCAN_LAYERS = [
  { id: 'hash', name: 'Layer 1: Local Hash DB', desc: 'SHA-256 lookup in ~39,000 signatures', time: 300 },
  { id: 'vt', name: 'Layer 2: VirusTotal API', desc: 'Checking 70+ AV engines (cloud)', time: 2000 },
  { id: 'heuristic', name: 'Layer 3: Heuristic Analysis', desc: 'Entropy + pattern + PE analysis', time: 500 },
  { id: 'anomaly', name: 'Layer 4: AI Anomaly Detection', desc: 'Isolation Forest ML model', time: 400 },
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
        File Scan
      </h1>
      <p className="text-gray-400 mb-8">Upload file to scan through 4-layer AI detection engine</p>

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
            <p className="text-emerald-400 font-medium">Scanning through 4 AI layers...</p>
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
            <p className="text-gray-300 font-medium">Drop file here or click to upload</p>
            <p className="text-gray-500 text-sm">Supports any file type • Max 32MB for VirusTotal</p>
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
          Test with EICAR File
        </button>
        <span className="text-gray-500 text-xs">Standard antivirus test file — NOT a real virus</span>
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
                  {result.detected ? '⚠️ THREAT DETECTED' : '✅ CLEAN — No Threats Found'}
                </h2>
                <p className="text-gray-300 mt-1">{result.message}</p>
              </div>
            </div>
          </div>

          {/* Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* File Info */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">File Info</h3>
              <div className="space-y-2 text-sm">
                <Row label="Filename" value={result.filename} />
                <Row label="Size" value={formatBytes(result.file_size)} />
                <Row label="Scan Time" value={`${result.scan_time}s`} />
                <Row label="Method" value={result.method} />
              </div>
            </div>

            {/* Threat Info */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Threat Analysis</h3>
              <div className="space-y-2 text-sm">
                <Row label="Threat Level" value={
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
                <Row label="Confidence" value={`${((result.confidence || 0) * 100).toFixed(1)}%`} />
                {result.threat_name && <Row label="Threat Name" value={result.threat_name} />}
                {result.vt_link && (
                  <Row label="VirusTotal" value={
                    <a href={result.vt_link} target="_blank" rel="noopener noreferrer"
                       className="text-blue-400 hover:underline flex items-center gap-1">
                      View Report <ExternalLink className="w-3 h-3" />
                    </a>
                  } />
                )}
              </div>
            </div>
          </div>

          {/* VT Stats */}
          {result.vt_stats && result.vt_stats.total > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">VirusTotal Results</h3>
              <div className="flex gap-6 flex-wrap">
                <VTStat label="Malicious" value={result.vt_stats.malicious} color="text-red-400" />
                <VTStat label="Suspicious" value={result.vt_stats.suspicious} color="text-amber-400" />
                <VTStat label="Undetected" value={result.vt_stats.undetected} color="text-green-400" />
                <VTStat label="Total Engines" value={result.vt_stats.total} color="text-blue-400" />
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
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Layer-by-Layer Analysis</h3>
              <div className="space-y-3">
                {result.layers.hash_local && (
                  <LayerRow name="Layer 1: Local Hash DB" result={result.layers.hash_local} />
                )}
                {result.layers.virustotal && (
                  <LayerRow name="Layer 2: VirusTotal" result={result.layers.virustotal} />
                )}
                {result.layers.heuristic && (
                  <LayerRow name="Layer 3: Heuristic" result={result.layers.heuristic} />
                )}
                {result.layers.anomaly_detection && (
                  <LayerRow name="Layer 4: AI Anomaly Detection" result={result.layers.anomaly_detection} />
                )}
              </div>
            </div>
          )}

          {/* Anomaly Detection Details */}
          {result.layers?.anomaly_detection?.features && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-5 h-5 text-purple-400" />
                <h3 className="text-sm font-semibold text-white uppercase">AI Anomaly Analysis (Isolation Forest)</h3>
                <span className={`text-xs px-2 py-0.5 rounded ml-auto ${result.layers.anomaly_detection.detected ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                  {result.layers.anomaly_detection.prediction?.toUpperCase()}
                </span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                <FeatureCard label="Entropy" value={result.layers.anomaly_detection.features.entropy?.toFixed(2)} warn={result.layers.anomaly_detection.features.entropy > 7.0} />
                <FeatureCard label="Suspicious Patterns" value={result.layers.anomaly_detection.features.suspicious_patterns} warn={result.layers.anomaly_detection.features.suspicious_patterns > 3} />
                <FeatureCard label="Network Patterns" value={result.layers.anomaly_detection.features.network_patterns} warn={result.layers.anomaly_detection.features.network_patterns > 3} />
                <FeatureCard label="Anomaly Score" value={result.layers.anomaly_detection.anomaly_score?.toFixed(3)} warn={result.layers.anomaly_detection.anomaly_score < 0} />
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <FeatureCard label="Is PE" value={result.layers.anomaly_detection.features.is_pe ? 'Yes' : 'No'} />
                <FeatureCard label="Null Byte Ratio" value={(result.layers.anomaly_detection.features.null_byte_ratio * 100).toFixed(1) + '%'} />
                <FeatureCard label="Printable Ratio" value={(result.layers.anomaly_detection.features.printable_ratio * 100).toFixed(1) + '%'} />
                <FeatureCard label="Unique Bytes" value={result.layers.anomaly_detection.features.unique_bytes} />
              </div>
            </div>
          )}

          {/* Heuristic Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Heuristic Reasons</h3>
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
        {detected ? 'DETECTED' : result.error ? 'ERROR' : result.message === 'Not found in VirusTotal database' ? 'NOT IN DB' : 'CLEAN'}
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
