import { useState, useEffect } from 'react';
import { Shield, ShieldCheck, ShieldAlert, Activity, FileSearch, Globe, ShieldX, Brain, Cpu, Database, Layers, FlaskConical } from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, CartesianGrid, Legend } from 'recharts';
import { getStats, getHealth } from '../api';

const COLORS = {
  safe: '#34d399',
  low: '#facc15',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
  unknown: '#6b7280',
};

const METHOD_COLORS = {
  hash_local: '#34d399',
  virustotal: '#60a5fa',
  heuristic: '#f59e0b',
  anomaly_detection: '#a78bfa',
  all_clear: '#6b7280',
  waf: '#f87171',
};

const TYPE_COLORS = {
  file: '#60a5fa',
  url: '#34d399',
  waf: '#f59e0b',
};

function StatCard({ icon: Icon, label, value, color }) {
  const colors = {
    emerald: 'bg-emerald-500/20 text-emerald-400',
    red: 'bg-red-500/20 text-red-400',
    blue: 'bg-blue-500/20 text-blue-400',
    amber: 'bg-amber-500/20 text-amber-400',
    purple: 'bg-purple-500/20 text-purple-400',
    cyan: 'bg-cyan-500/20 text-cyan-400',
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center gap-4">
        <div className={`p-3 rounded-lg ${colors[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="text-2xl font-bold text-white">{value}</p>
        </div>
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs">
        <p className="text-white font-medium">{payload[0].name || payload[0].payload?.name}</p>
        <p className="text-gray-300">{payload[0].value}</p>
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [s, h] = await Promise.all([getStats(), getHealth()]);
      setStats(s);
      setHealth(h);
      setError(null);
    } catch (e) {
      setError('Không thể kết nối đến máy chủ API. Hãy chắc chắn backend đang chạy trên cổng 8000.');
    }
  }

  // Prepare chart data
  const charts = stats?.charts || {};

  const threatPieData = Object.entries(charts.threat_distribution || {}).map(([name, value]) => ({
    name: name.toUpperCase(), value, fill: COLORS[name] || COLORS.unknown,
  }));

  const methodBarData = Object.entries(charts.method_distribution || {}).map(([name, value]) => ({
    name: name.replace('_', ' '), fullName: name, value, fill: METHOD_COLORS[name] || '#6b7280',
  }));

  const typeBarData = Object.entries(charts.type_distribution || {}).map(([name, value]) => ({
    name: name.toUpperCase(), fullName: name, value, fill: TYPE_COLORS[name] || '#6b7280',
  }));

  const attackBarData = Object.entries(charts.attack_distribution || {}).map(([name, value]) => ({
    name, value,
  }));

  // Timeline: group by minute for area chart
  const timelineData = (charts.recent_timeline || []).map((entry, idx) => {
    const t = entry.timestamp ? new Date(entry.timestamp) : null;
    return {
      idx: idx + 1,
      time: t ? t.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }) : `#${idx + 1}`,
      threat: entry.detected ? 1 : 0,
      clean: entry.detected ? 0 : 1,
    };
  });

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
        <ShieldX className="w-16 h-16 text-red-400" />
        <h2 className="text-xl font-bold text-red-400">Lỗi kết nối</h2>
        <p className="text-gray-400 text-center max-w-md">{error}</p>
        <code className="text-gray-500 text-sm bg-gray-900 px-4 py-2 rounded-lg">
          cd src/api && uvicorn server:app --reload --port 8000
        </code>
        <button onClick={loadData} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm transition-colors">
          Thử lại
        </button>
      </div>
    );
  }

  const hasChartData = threatPieData.length > 0 || methodBarData.length > 0;

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400" />
          Tổng quan
        </h1>
        <p className="text-gray-400 mt-1">HThuong Antivirus AI — Tổng quan hệ thống</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        <StatCard icon={Activity} label="Tổng lượt quét" value={stats?.total_scans ?? '—'} color="blue" />
        <StatCard icon={ShieldAlert} label="Mối đe dọa" value={stats?.threats_detected ?? '—'} color="red" />
        <StatCard icon={FileSearch} label="Tệp đã quét" value={stats?.files_scanned ?? '—'} color="emerald" />
        <StatCard icon={Globe} label="URL đã quét" value={stats?.urls_scanned ?? '—'} color="cyan" />
        <StatCard icon={ShieldX} label="WAF chặn" value={stats?.waf_blocked ?? '—'} color="amber" />
        <StatCard icon={ShieldCheck} label="Lượt WAF" value={stats?.waf_checks ?? '—'} color="purple" />
      </div>

      {/* Charts Row 1 — Threat Distribution + Scan Types */}
      {hasChartData && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
          {/* Threat Level Pie */}
          {threatPieData.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase mb-4">Phân bố mức độ đe dọa</h2>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={threatPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                  >
                    {threatPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    verticalAlign="middle"
                    align="right"
                    layout="vertical"
                    formatter={(val) => <span className="text-xs text-gray-300">{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Scan Type Bar */}
          {typeBarData.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase mb-4">Loại quét</h2>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={typeBarData} barSize={40}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {typeBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* Charts Row 2 — Detection Methods + Attack Types */}
      {hasChartData && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
          {/* Detection Method Bar */}
          {methodBarData.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase mb-4">Phương thức phát hiện</h2>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={methodBarData} barSize={32} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 12 }} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} width={100} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                    {methodBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* WAF Attack Types */}
          {attackBarData.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase mb-4">Loại tấn công WAF</h2>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={attackBarData} barSize={32}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" fill="#f87171" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* Scan Timeline */}
      {timelineData.length > 2 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
          <h2 className="text-sm font-semibold text-gray-400 uppercase mb-4">Dòng thời gian quét gần đây</h2>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#d1d5db' }}
              />
              <Area type="monotone" dataKey="clean" stackId="1" stroke="#34d399" fill="#34d39940" name="An toàn" />
              <Area type="monotone" dataKey="threat" stackId="1" stroke="#ef4444" fill="#ef444440" name="Đe dọa" />
              <Legend formatter={(val) => <span className="text-xs text-gray-300">{val}</span>} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* No data message */}
      {!hasChartData && stats && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 mb-8 text-center">
          <Activity className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">Chưa có dữ liệu quét. Bắt đầu quét để xem biểu đồ!</p>
        </div>
      )}

      {/* Engine Status */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
        <h2 className="text-lg font-semibold text-white mb-4">Trạng thái Engine</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {health && (
            <>
              <EngineCard
                name="Cơ sở dữ liệu Hash"
                detail={`${health.engines.hash_db?.toLocaleString()} chữ ký`}
                active={health.engines.hash_db > 0}
              />
              <EngineCard
                name="VirusTotal API"
                detail={health.engines.virustotal ? `Đã kết nối · Cache: ${health.vt_cache_size}` : 'Chưa cấu hình'}
                active={health.engines.virustotal}
              />
              <EngineCard
                name="Engine Heuristic"
                detail="Phân tích Entropy + Mẫu"
                active={health.engines.heuristic}
              />
              <EngineCard
                name="Engine WAF"
                detail="SQLi · XSS · CMDi · Duyệt đường dẫn"
                active={health.engines.waf}
              />
              <EngineCard
                name="WAF ML (Trí tuệ nhân tạo)"
                detail={health.ml_waf_info?.loaded
                  ? `TF-IDF + Random Forest · Độ chính xác: ${(health.ml_waf_info.test_accuracy * 100).toFixed(1)}%`
                  : 'Chưa tải mô hình'}
                active={health.engines.ml_waf}
                isML
              />
              <EngineCard
                name="Phát hiện bất thường (AI)"
                detail={health.anomaly_info?.loaded
                  ? `Isolation Forest · ${health.anomaly_info.metadata?.trained_samples} mẫu`
                  : 'Chưa tải mô hình'}
                active={health.engines.anomaly_detection}
                isML
              />
            </>
          )}
        </div>
      </div>

      {/* ML Model Details */}
      {health?.ml_waf_info?.loaded && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-400" />
            Mô hình AI / ML
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* WAF ML */}
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-purple-400 mb-3">Bộ phân loại WAF ML</h3>
              <div className="space-y-2 text-sm">
                <MLRow label="Mô hình" value="TF-IDF + Random Forest" />
                <MLRow label="Độ chính xác (Test)" value={`${(health.ml_waf_info.test_accuracy * 100).toFixed(1)}%`} />
                <MLRow label="Độ chính xác (CV)" value={health.ml_waf_info.cv_accuracy ? `${(health.ml_waf_info.cv_accuracy * 100).toFixed(1)}%` : 'N/A'} />
                <MLRow label="Số đặc trưng" value={health.ml_waf_info.feature_count?.toLocaleString()} />
                <MLRow label="Mẫu huấn luyện" value={health.ml_waf_info.train_samples} />
                <MLRow label="Lớp phân loại" value={health.ml_waf_info.classes?.join(', ')} />
                <MLRow label="Thời gian huấn luyện" value={health.ml_waf_info.trained_at} />
              </div>
            </div>

            {/* Anomaly Detection */}
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-purple-400 mb-3">Phát hiện bất thường</h3>
              <div className="space-y-2 text-sm">
                <MLRow label="Mô hình" value="Isolation Forest (Không giám sát)" />
                <MLRow label="Tổng mẫu" value={health.anomaly_info?.metadata?.trained_samples} />
                <MLRow label="Mẫu bình thường" value={health.anomaly_info?.metadata?.normal_samples} />
                <MLRow label="Tỉ lệ nhiễm" value={`${(health.anomaly_info?.metadata?.contamination || 0) * 100}%`} />
                <MLRow label="Số cây" value={health.anomaly_info?.metadata?.n_estimators} />
                <MLRow label="Số đặc trưng" value={health.anomaly_info?.metadata?.features?.length || 0} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Benchmark Results */}
      {health?.benchmark && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-amber-400" />
            Kết quả đánh giá WAF
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(health.benchmark).map(([method, data]) => (
              <div key={method} className="bg-gray-800 rounded-lg p-4">
                <h3 className={`text-sm font-semibold mb-3 ${
                  method.includes('Hybrid') ? 'text-emerald-400' :
                  method.includes('ML') ? 'text-purple-400' : 'text-blue-400'
                }`}>{method}</h3>
                <div className="space-y-2 text-sm">
                  <MLRow label="Độ chính xác" value={`${(data.accuracy * 100).toFixed(1)}%`} />
                  <MLRow label="Macro F1" value={`${(data.macro_f1 * 100).toFixed(1)}%`} />
                  <MLRow label="Tỉ lệ phát hiện" value={`${(data.detection_rate * 100).toFixed(1)}%`} />
                  <MLRow label="Dương tính giả" value={`${(data.false_positive_rate * 100).toFixed(2)}%`} />
                  <MLRow label="Tốc độ" value={`${data.speed_payloads_per_sec?.toFixed(0)} req/s`} />
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-3">
            Tập dữ liệu: {health.benchmark?.['Hybrid (Regex+ML)']?.total_samples || 443} payload ·
            Đánh giá trên toàn bộ tập dữ liệu
          </p>
        </div>
      )}

      {/* Architecture Info */}
      {health?.architecture && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            Kiến trúc hệ thống
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-cyan-400 mb-3">Các tầng phát hiện</h3>
              <div className="space-y-2 text-sm">
                <MLRow label="Tổng số tầng" value={health.architecture.detection_layers} />
                <MLRow label="Tầng 1" value="Hash DB (SHA-256, O(1))" />
                <MLRow label="Tầng 2" value="VirusTotal API (70+ AV)" />
                <MLRow label="Tầng 3" value="Heuristic (Entropy + PE)" />
                <MLRow label="Tầng 4" value="Isolation Forest (ML)" />
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-cyan-400 mb-3">Chi tiết WAF</h3>
              <div className="space-y-2 text-sm">
                <MLRow label="Tổng mẫu nhận diện" value={health.architecture.waf_patterns.total} />
                <MLRow label="Mẫu SQLi" value={health.architecture.waf_patterns.sqli} />
                <MLRow label="Mẫu XSS" value={health.architecture.waf_patterns.xss} />
                <MLRow label="Mẫu CMDi" value={health.architecture.waf_patterns.cmdi} />
                <MLRow label="Duyệt đường dẫn" value={health.architecture.waf_patterns.path_traversal} />
                <MLRow label="Tiền xử lý" value={health.architecture.preprocessing?.join(', ')} />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function MLRow({ label, value }) {
  return (
    <div className="flex justify-between">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-200">{value ?? '—'}</span>
    </div>
  );
}

function EngineCard({ name, detail, active, isML }) {
  return (
    <div className={`p-4 rounded-lg border ${active ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
      <div className="flex items-center gap-2 mb-1">
        <div className={`w-2 h-2 rounded-full ${active ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
        <span className="text-sm font-medium text-white">{name}</span>
        {isML && <Brain className="w-3.5 h-3.5 text-purple-400 ml-auto" />}
      </div>
      <p className="text-xs text-gray-400">{detail}</p>
    </div>
  );
}
