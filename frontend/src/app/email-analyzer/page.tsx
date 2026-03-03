'use client';
import { useState } from 'react';
import RiskBadge from '@/components/RiskBadge';
import RiskGauge from '@/components/RiskGauge';
import ReasonList from '@/components/ReasonList';

interface LLMVerdict {
  verdict: 'Phishing' | 'Legitimate' | 'Suspicious';
  confidence: number;
  summary: string;
  red_flags: string[];
}

interface EmailResult {
  risk_score: number;
  classification: string;
  reasons: string[];
  urls: string[];
  sender_domain: string;
  llm_verdict: LLMVerdict | null;
}

export default function EmailAnalyzerPage() {
  const [emailText, setEmailText] = useState('');
  const [senderDomain, setSenderDomain] = useState('');
  const [result, setResult] = useState<EmailResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch('/api/analyze/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText, sender_domain: senderDomain || undefined }),
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
        <h1 className="text-2xl font-bold text-slate-900">Email Phishing Analyzer</h1>
        <p className="text-slate-500 text-sm mt-1">Paste raw email content to detect urgency patterns, link mismatches, and suspicious signals.</p>
      </div>

      {/* Input card */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6 space-y-4">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">
              Sender Domain <span className="text-slate-400 font-normal normal-case">(optional)</span>
            </label>
            <input
              type="text"
              value={senderDomain}
              onChange={(e) => setSenderDomain(e.target.value)}
              placeholder="e.g. paypal.com"
              className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">
              Email Content
            </label>
            <textarea
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
              placeholder="Paste the full email content here, including headers if available…"
              required
              rows={10}
              className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition resize-y font-mono"
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
                Analyzing…
              </>
            ) : 'Analyze Email'}
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
            <div className="space-y-2">
              <p className="text-xs text-slate-400 font-medium uppercase tracking-wide">Analysis Result</p>
              {result.sender_domain && (
                <p className="text-sm text-slate-500">Sender domain: <span className="font-medium text-slate-700">{result.sender_domain}</span></p>
              )}
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

          {/* LLM Verdict */}
          {result.llm_verdict && (
            <div className="p-6 border-t border-slate-100">
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">AI Analysis (Groq / Llama 3.1)</p>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold border ${
                    result.llm_verdict.verdict === 'Phishing'   ? 'bg-red-50 text-red-700 border-red-200' :
                    result.llm_verdict.verdict === 'Suspicious' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                    'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      result.llm_verdict.verdict === 'Phishing' ? 'bg-red-500' :
                      result.llm_verdict.verdict === 'Suspicious' ? 'bg-amber-500' : 'bg-emerald-500'
                    }`} />
                    {result.llm_verdict.verdict}
                  </span>
                  <span className="text-xs text-slate-500">{result.llm_verdict.confidence}% confidence</span>
                </div>
                <p className="text-sm text-slate-700">{result.llm_verdict.summary}</p>
                {result.llm_verdict.red_flags.length > 0 && (
                  <ul className="space-y-1">
                    {result.llm_verdict.red_flags.map((f, i) => (
                      <li key={i} className="text-xs text-red-600 flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-red-400 shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Extracted URLs */}
          {result.urls.length > 0 && (
            <div className="p-6">
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                URLs Found in Email ({result.urls.length})
              </p>
              <ul className="space-y-2">
                {result.urls.map((u, i) => (
                  <li key={i} className="flex items-center gap-2 bg-amber-50 border border-amber-100 text-amber-800 text-xs px-3 py-2 rounded-lg font-mono break-all">
                    <svg className="w-3.5 h-3.5 shrink-0 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
                    </svg>
                    {u}
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
