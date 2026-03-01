import { useState, useEffect } from 'react';
import { Shield, ShieldCheck, ShieldAlert, Activity, FileSearch, Globe, ShieldX } from 'lucide-react';
import { getStats, getHealth } from '../api';

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
      setError('Cannot connect to API server. Make sure backend is running on port 8000.');
    }
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
        <ShieldX className="w-16 h-16 text-red-400" />
        <h2 className="text-xl font-bold text-red-400">Connection Error</h2>
        <p className="text-gray-400 text-center max-w-md">{error}</p>
        <code className="text-gray-500 text-sm bg-gray-900 px-4 py-2 rounded-lg">
          cd src/api && uvicorn server:app --reload --port 8000
        </code>
        <button onClick={loadData} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm transition-colors">
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400" />
          Dashboard
        </h1>
        <p className="text-gray-400 mt-1">HThuong Antivirus AI — System Overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        <StatCard icon={Activity} label="Total Scans" value={stats?.total_scans ?? '—'} color="blue" />
        <StatCard icon={ShieldAlert} label="Threats Detected" value={stats?.threats_detected ?? '—'} color="red" />
        <StatCard icon={FileSearch} label="Files Scanned" value={stats?.files_scanned ?? '—'} color="emerald" />
        <StatCard icon={Globe} label="URLs Scanned" value={stats?.urls_scanned ?? '—'} color="cyan" />
        <StatCard icon={ShieldX} label="WAF Blocked" value={stats?.waf_blocked ?? '—'} color="amber" />
        <StatCard icon={ShieldCheck} label="WAF Checks" value={stats?.waf_checks ?? '—'} color="purple" />
      </div>

      {/* Engine Status */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Engine Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {health && (
            <>
              <EngineCard
                name="Hash Database"
                detail={`${health.engines.hash_db} signatures`}
                active={health.engines.hash_db > 0}
              />
              <EngineCard
                name="VirusTotal API"
                detail={health.engines.virustotal ? 'Connected' : 'Not configured'}
                active={health.engines.virustotal}
              />
              <EngineCard
                name="Heuristic Engine"
                detail="Entropy + Pattern Analysis"
                active={health.engines.heuristic}
              />
              <EngineCard
                name="WAF Engine"
                detail="SQLi · XSS · CMDi"
                active={health.engines.waf}
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function EngineCard({ name, detail, active }) {
  return (
    <div className={`p-4 rounded-lg border ${active ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
      <div className="flex items-center gap-2 mb-1">
        <div className={`w-2 h-2 rounded-full ${active ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
        <span className="text-sm font-medium text-white">{name}</span>
      </div>
      <p className="text-xs text-gray-400">{detail}</p>
    </div>
  );
}
