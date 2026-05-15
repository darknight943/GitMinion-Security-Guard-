'use client';

/**
 * Scanner Component
 * 
 * This component provides the UI for scanning package.json files
 * for security vulnerabilities. It will include:
 * - Text area for package.json input
 * - Scan button to trigger vulnerability check
 * - Loading state during scanning
 * - Error handling for invalid inputs
 * 
 * @component
 */

import { useState, useRef } from 'react';
import { DEFAULT_PACKAGE_JSON } from '@/lib/parser';
import { getScoreLabel } from '@/lib/score';
import ResultCard from './ResultCard';

interface VulnResult {
  type: 'vuln';
  package: string;
  version: string;
  osvId: string;
  what: string;
  impact: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  fix: string;
  rawAnalysis?: string;
}

interface MetaResult {
  type: 'meta';
  riskScore: number;
  totalDeps: number;
  vulnerableCount: number;
  warning?: string;
}

export default function Scanner() {
  const [packageJson, setPackageJson] = useState(DEFAULT_PACKAGE_JSON);
  const [status, setStatus] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  const [statusMessage, setStatusMessage] = useState('');
  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [totalDeps, setTotalDeps] = useState(0);
  const [vulnerableCount, setVulnerableCount] = useState(0);
  const [vulns, setVulns] = useState<VulnResult[]>([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [jsonError, setJsonError] = useState('');
  const [warning, setWarning] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const handleJsonChange = (value: string) => {
    setPackageJson(value);
    try {
      JSON.parse(value);
      setJsonError('');
    } catch {
      setJsonError('⚠ Invalid JSON');
    }
  };

  const handleScan = async () => {
    if (jsonError) {
      setErrorMessage(jsonError);
      setStatus('error');
      return;
    }

    setStatus('scanning');
    setStatusMessage('Parsing dependencies...');
    setVulns([]);
    setRiskScore(null);
    setTotalDeps(0);
    setVulnerableCount(0);
    setErrorMessage('');
    setWarning('');

    abortControllerRef.current = new AbortController();
    const timeoutId = setTimeout(() => {
      abortControllerRef.current?.abort();
    }, 15000);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ packageJson }),
        signal: abortControllerRef.current.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Scan failed');
      }

      setStatusMessage('Querying OSV vulnerability database...');

      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error('No response body');
      }

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;

          try {
            const chunk = JSON.parse(line);

            if (chunk.type === 'meta') {
              const meta = chunk as MetaResult;
              setRiskScore(meta.riskScore);
              setTotalDeps(meta.totalDeps);
              setVulnerableCount(meta.vulnerableCount);
              setWarning(meta.warning || '');
              setStatusMessage('Groq is analyzing vulnerabilities...');
            } else if (chunk.type === 'vuln') {
              const vuln = chunk as VulnResult;
              setVulns((prev) => [...prev, vuln]);
            }
          } catch (e) {
            console.error('Failed to parse chunk:', line);
          }
        }
      }

      setStatus('done');
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        setStatus('error');
        setErrorMessage('Request timed out. Try again.');
      } else {
        setStatus('error');
        setErrorMessage(error instanceof Error ? error.message : 'An unknown error occurred');
      }
    }
  };

  const handleScanAgain = () => {
    setStatus('idle');
    setVulns([]);
    setRiskScore(null);
    setTotalDeps(0);
    setVulnerableCount(0);
    setErrorMessage('');
    setWarning('');
    textareaRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const { label: scoreLabel, color: scoreColor } = getScoreLabel(riskScore || 0);

  return (
    <div className="min-h-screen bg-background text-foreground p-8">
      <div className="max-w-4xl mx-auto">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h1 className="text-6xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            DepSentry
          </h1>
          <p className="text-xl text-muted-foreground">
            Paste your package.json. Get plain-English vulnerability reports instantly.
          </p>
        </div>

        {/* Input Section */}
        <div className="mb-8">
          <textarea
            ref={textareaRef}
            value={packageJson}
            onChange={(e) => handleJsonChange(e.target.value)}
            className="w-full h-80 bg-card border border-border rounded-lg p-4 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary"
            placeholder="Paste your package.json here..."
          />
          {jsonError && (
            <p className="mt-2 text-sm text-red-400">{jsonError}</p>
          )}
          <button
            onClick={handleScan}
            disabled={status === 'scanning' || jsonError !== ''}
            className="mt-4 w-full bg-primary text-primary-foreground py-3 px-6 rounded-lg font-semibold hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {status === 'scanning' ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </span>
            ) : (
              'Scan Dependencies'
            )}
          </button>
        </div>

        {/* Status Bar */}
        {status === 'scanning' && (
          <div className="mb-8 p-4 bg-card border border-border rounded-lg">
            <p className="text-center text-muted-foreground">{statusMessage}</p>
          </div>
        )}

        {/* Results Section */}
        {status === 'done' && (
          <div className="space-y-6">
            {/* Warning Banner */}
            {warning && (
              <div className="p-4 bg-yellow-950/30 border border-yellow-500/30 rounded-lg">
                <p className="text-sm text-yellow-400">⚠ {warning}</p>
              </div>
            )}
            {vulnerableCount === 0 ? (
              <div className="p-8 bg-green-950/30 border border-green-500/30 rounded-lg text-center">
                <div className="text-6xl mb-4">✓</div>
                <h2 className="text-2xl font-bold text-green-400 mb-2">All Clear!</h2>
                <p className="text-muted-foreground">No known vulnerabilities found.</p>
                <button
                  onClick={handleScanAgain}
                  className="mt-4 bg-primary text-primary-foreground py-2 px-6 rounded-lg font-semibold hover:bg-primary/90 transition-colors"
                >
                  Scan Again
                </button>
              </div>
            ) : (
              <>
                {/* Risk Score Display */}
                <div className="p-6 bg-card border border-border rounded-lg text-center">
                  <div className={`text-7xl font-bold ${scoreColor} mb-2`}>
                    {riskScore}
                  </div>
                  <div className={`text-xl ${scoreColor} mb-2`}>{scoreLabel}</div>
                  <p className="text-muted-foreground">
                    {vulnerableCount} of {totalDeps} packages affected
                  </p>
                </div>

                {/* Vulnerability Cards */}
                <div className="space-y-4">
                  {vulns.map((vuln, index) => (
                    <ResultCard
                      key={`${vuln.osvId}-${index}`}
                      package={vuln.package}
                      version={vuln.version}
                      osvId={vuln.osvId}
                      severity={vuln.severity}
                      what={vuln.what}
                      impact={vuln.impact}
                      fix={vuln.fix}
                      rawAnalysis={vuln.rawAnalysis}
                    />
                  ))}
                </div>

                {/* Scan Again Button */}
                <button
                  onClick={handleScanAgain}
                  className="w-full bg-primary text-primary-foreground py-3 px-6 rounded-lg font-semibold hover:bg-primary/90 transition-colors"
                >
                  Scan Again
                </button>
              </>
            )}
          </div>
        )}

        {/* Error Section */}
        {status === 'error' && (
          <div className="p-6 bg-red-950/30 border border-red-500/30 rounded-lg">
            <h2 className="text-xl font-bold text-red-400 mb-2">Error</h2>
            <p className="text-red-300">{errorMessage}</p>
          </div>
        )}
      </div>
    </div>
  );
}