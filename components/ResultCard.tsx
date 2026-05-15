'use client';

/**
 * ResultCard Component
 * 
 * Displays a single vulnerability result with:
 * - CVE/ID information
 * - Severity level (Critical, High, Medium, Low)
 * - Affected package and version
 * - Description and remediation steps
 * - Links to detailed information
 * 
 * @component
 */

import { useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface ResultCardProps {
  package: string;
  version: string;
  osvId: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  what: string;
  impact: string;
  fix: string;
}

const getSeverityColor = (severity: string): string => {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500 text-white hover:bg-red-600';
    case 'High':
      return 'bg-orange-500 text-white hover:bg-orange-600';
    case 'Medium':
      return 'bg-yellow-500 text-black hover:bg-yellow-600';
    case 'Low':
      return 'bg-gray-500 text-white hover:bg-gray-600';
    default:
      return 'bg-gray-500 text-white hover:bg-gray-600';
  }
};

export default function ResultCard({
  package: pkg,
  version,
  osvId,
  severity,
  what,
  impact,
  fix,
}: ResultCardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(fix);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="animate-in fade-in slide-in-from-bottom-4 duration-500">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-1">
              {pkg}@{version}
            </h3>
          </div>
          <Badge className={getSeverityColor(severity)}>
            {severity}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* What's broken */}
        <div>
          <h4 className="text-sm font-semibold text-muted-foreground mb-2">What&apos;s broken:</h4>
          <p className="text-sm">{what}</p>
        </div>

        {/* Impact */}
        <div>
          <h4 className="text-sm font-semibold text-muted-foreground mb-2">Impact:</h4>
          <p className="text-sm">{impact}</p>
        </div>

        {/* Fix */}
        <div>
          <h4 className="text-sm font-semibold text-muted-foreground mb-2">Fix:</h4>
          <div className="relative">
            <pre className="bg-muted p-3 rounded-md text-sm font-mono overflow-x-auto">
              <code>{fix}</code>
            </pre>
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 p-1.5 rounded-md bg-background border border-border hover:bg-muted transition-colors"
              title="Copy to clipboard"
            >
              {copied ? (
                <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              )}
            </button>
          </div>
        </div>

        {/* OSV ID link */}
        <div className="pt-2 border-t border-border">
          <a
            href={`https://osv.dev/vulnerability/${osvId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-muted-foreground hover:text-primary transition-colors"
          >
            {osvId}
          </a>
        </div>
      </CardContent>
    </Card>
  );
}