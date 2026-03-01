import { useState } from 'react';
import { ShieldAlert, Send, ShieldCheck, ShieldX, Loader2 } from 'lucide-react';
import { checkWAF } from '../api';

const EXAMPLE_PAYLOADS = [
  { label: "SQL Injection", payload: "' OR 1=1 --" },
  { label: "SQL Union", payload: "' UNION SELECT username, password FROM users --" },
  { label: "XSS Script", payload: '<script>alert("XSS")</script>' },
  { label: "XSS Img", payload: '<img src=x onerror=alert(document.cookie)>' },
  { label: "Command Injection", payload: "; cat /etc/passwd" },
  { label: "Path Traversal", payload: "../../../etc/passwd" },
  { label: "Safe Input", payload: "Hello, this is a normal search query" },
];

export default function WAFCheck() {
  const [payload, setPayload] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleCheck(e) {
    e.preventDefault();
    if (!payload.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await checkWAF(payload);
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
        <ShieldAlert className="w-8 h-8 text-emerald-400" />
        WAF Test
      </h1>
      <p className="text-gray-400 mb-8">Test Web Application Firewall — Detect SQL Injection, XSS, Command Injection</p>

      {/* Input */}
      <form onSubmit={handleCheck} className="mb-6">
        <div className="flex gap-3">
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter payload to test... e.g. ' OR 1=1 --"
            rows={3}
            className="flex-1 px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-emerald-500 focus:outline-none font-mono text-sm resize-none"
          />
          <button
            type="submit"
            disabled={loading || !payload.trim()}
            className="px-6 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors self-end flex items-center gap-2 py-3"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            Check
          </button>
        </div>
      </form>

      {/* Example Payloads */}
      <div className="mb-6">
        <p className="text-xs text-gray-500 mb-2">Quick test payloads:</p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLE_PAYLOADS.map((ex, i) => (
            <button key={i}
              onClick={() => setPayload(ex.payload)}
              className="text-xs px-3 py-1.5 bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
            >
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">{error}</div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-4">
          {/* Status Banner */}
          <div className={`p-6 rounded-xl border ${
            result.detected
              ? 'bg-red-500/10 border-red-500/30'
              : 'bg-emerald-500/10 border-emerald-500/30'
          }`}>
            <div className="flex items-center gap-4">
              {result.detected ? (
                <ShieldX className="w-12 h-12 text-red-400" />
              ) : (
                <ShieldCheck className="w-12 h-12 text-emerald-400" />
              )}
              <div>
                <h2 className={`text-2xl font-bold ${result.detected ? 'text-red-400' : 'text-emerald-400'}`}>
                  {result.action === 'BLOCKED' ? '🚫 BLOCKED — Attack Detected' : '✅ ALLOWED — Safe Input'}
                </h2>
                {result.attacks && result.attacks.length > 0 && (
                  <div className="flex gap-2 mt-2">
                    {result.attacks.map((a, i) => (
                      <span key={i} className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded">
                        {a}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Detail cards */}
          {result.details && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <AttackCard name="SQL Injection" data={result.details.sqli} />
              <AttackCard name="Cross-Site Scripting (XSS)" data={result.details.xss} />
              <AttackCard name="Command Injection" data={result.details.command_injection} />
              <AttackCard name="Path Traversal" data={result.details.path_traversal} />
            </div>
          )}

          {/* Tested Payload */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Tested Payload</h3>
            <code className="text-sm text-amber-300 bg-gray-800 px-3 py-2 rounded block break-all">
              {result.payload}
            </code>
          </div>
        </div>
      )}
    </div>
  );
}

function AttackCard({ name, data }) {
  if (!data) return null;
  return (
    <div className={`p-4 rounded-xl border ${
      data.detected ? 'bg-red-500/5 border-red-500/30' : 'bg-gray-900 border-gray-800'
    }`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-white">{name}</span>
        <span className={`text-xs px-2 py-0.5 rounded font-medium ${
          data.detected ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
        }`}>
          {data.detected ? 'DETECTED' : 'CLEAN'}
        </span>
      </div>
      <div className="flex justify-between text-xs text-gray-500">
        <span>Matched rules: {data.matched_rules}</span>
        <span>Severity: {data.severity}</span>
      </div>
      {data.detected && (
        <div className="mt-2 h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div className="h-full bg-red-500 rounded-full" style={{ width: `${data.confidence * 100}%` }} />
        </div>
      )}
    </div>
  );
}
