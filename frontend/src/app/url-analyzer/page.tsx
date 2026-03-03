'use client';
import { useState } from 'react';
import RiskBadge from '@/components/RiskBadge';
import RiskGauge from '@/components/RiskGauge';
import ReasonList from '@/components/ReasonList';

interface AnalysisResult {
  url: string;
  risk_score: number;
  classification: string;
  reasons: string[];
  threat_intel: { malicious: number; suspicious: number } | null;
  domain_age: { created_at: string | null; age_days: number | null; is_young: boolean } | null;
  safe_browsing: { safe: boolean; threats: string[] } | null;
  ml_prediction: { prediction: string; probability: number } | null;
}

export default function URLAnalyzerPage() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch('/api/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) {
        const text = await res.text();
        let data: { errors?: { msg: string }[]; error?: string } = {};
        try { data = JSON.parse(text); } catch { /* non-JSON error body */ }
        throw new Error(data.errors?.[0]?.msg || data.error || `Analysis failed (${res.status})`);
      }
      setResult(await res.json());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900">URL Risk Analyzer</h1>
        <p className="text-slate-500 text-sm mt-1">Paste any URL to scan it for phishing signals, typosquatting, and threat intelligence.</p>
      </div>

      {/* Input card */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6">
        <form onSubmit={handleSubmit} className="flex gap-3">
          <div className="flex-1 relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m6.1-6.1a4 4 0 015.656 0l-4 4a4 4 0 01-5.656-5.656l1.102-1.101" />
            </svg>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-site.com/login"
              required
              className="w-full pl-9 pr-4 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white text-sm font-semibold rounded-lg shadow-sm transition-colors"
          >
            {loading ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/>
                </svg>
                Scanning…
              </>
            ) : 'Scan URL'}
          </button>
        </form>
      </div>

      {error && (
        <div className="flex items-center gap-2 bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
          <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          {error}
        </div>
      )}

      {result && (
        <div className="bg-white border border-slate-200 rounded-xl shadow-sm divide-y divide-slate-100">
          {/* Score row */}
          <div className="p-6 flex items-center justify-between gap-6 flex-wrap">
            <div className="space-y-2 min-w-0">
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wide">Scanned URL</p>
              <p className="text-sm text-slate-700 break-all font-mono">{result.url}</p>
              <RiskBadge classification={result.classification} />
            </div>
            <RiskGauge score={result.risk_score} />
          </div>

          {/* Risk factors */}
          {result.reasons.length > 0 && (
            <div className="p-6">
              <ReasonList reasons={result.reasons} />
            </div>
          )}

          {/* Intelligence panels */}
          <div className="p-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {result.threat_intel && (
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">VirusTotal</p>
                <div className="flex gap-4">
                  <div>
                    <p className="text-xl font-bold text-red-600">{result.threat_intel.malicious}</p>
                    <p className="text-xs text-slate-500">Malicious</p>
                  </div>
                  <div>
                    <p className="text-xl font-bold text-amber-600">{result.threat_intel.suspicious}</p>
                    <p className="text-xs text-slate-500">Suspicious</p>
                  </div>
                </div>
              </div>
            )}
            {result.domain_age && (
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Domain Age</p>
                {result.domain_age.age_days !== null ? (
                  <>
                    <p className={`text-xl font-bold ${result.domain_age.is_young ? 'text-red-600' : 'text-emerald-600'}`}>
                      {result.domain_age.age_days < 365
                        ? `${result.domain_age.age_days} days`
                        : `${Math.floor(result.domain_age.age_days / 365)} yr${Math.floor(result.domain_age.age_days / 365) !== 1 ? 's' : ''}`}
                    </p>
                    <p className="text-xs text-slate-500">Registered {result.domain_age.created_at}</p>
                    {result.domain_age.is_young && (
                      <p className="text-xs text-red-500 mt-1 font-medium">Recently registered</p>
                    )}
                  </>
                ) : (
                  <p className="text-sm text-slate-400">WHOIS data unavailable</p>
                )}
              </div>
            )}
            {result.safe_browsing && (
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Google Safe Browsing</p>
                {result.safe_browsing.safe ? (
                  <>
                    <p className="text-xl font-bold text-emerald-600">Clean</p>
                    <p className="text-xs text-slate-500">No threats detected</p>
                  </>
                ) : (
                  <>
                    <p className="text-xl font-bold text-red-600">Flagged</p>
                    <p className="text-xs text-red-500 mt-1 font-medium">{result.safe_browsing.threats.join(', ')}</p>
                  </>
                )}
              </div>
            )}
            {result.ml_prediction && (
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">ML Classifier</p>
                <p className="text-xl font-bold text-slate-800">{result.ml_prediction.prediction}</p>
                <p className="text-xs text-slate-500">{(result.ml_prediction.probability * 100).toFixed(1)}% confidence</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
