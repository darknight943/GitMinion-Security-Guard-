/**
 * Scan API Route
 * 
 * POST /api/scan
 * 
 * This API endpoint processes package.json files and returns
 * vulnerability scan results with streaming AI analysis. It will:
 * - Accept package.json content in request body
 * - Parse dependencies using lib/parser
 * - Query OSV database for vulnerabilities
 * - Use Groq AI for intelligent analysis with streaming
 * - Return structured vulnerability report as newline-delimited JSON
 * 
 * Request body:
 * {
 *   "packageJson": string
 * }
 * 
 * Response format (newline-delimited JSON):
 * {"type":"meta","riskScore":72,"totalDeps":6,"vulnerableCount":3}
 * {"type":"vuln","package":"react-scripts","version":"4.0.3","osvId":"CVE-xxx","groqExplanation":"{streamed text}","severity":"High","fix":"bump to 5.0.0"}
 */

import { NextRequest } from 'next/server';
import { parseDependencies } from '@/lib/parser';
import { queryOSV } from '@/lib/osv';
import { calculateRiskScore } from '@/lib/score';
import Groq from 'groq-sdk';

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { packageJson } = body;

    if (!packageJson) {
      return new Response('packageJson is required', { status: 400 });
    }

    // Step 1: Parse dependencies
    let deps;
    try {
      deps = parseDependencies(packageJson);
    } catch (error) {
      return new Response(error instanceof Error ? error.message : 'Invalid package.json', { status: 400 });
    }

    // Step 2: Query OSV
    const osvResults = await queryOSV(deps);

    // Step 3: Calculate risk score
    const riskScore = calculateRiskScore(osvResults);
    const vulnerableCount = osvResults.filter(r => r.vulns.length > 0).length;

    // Step 4: Create TransformStream for streaming response
    const encoder = new TextEncoder();
    const stream = new TransformStream({
      async start(controller) {
        try {
          // Emit meta first
          const meta = {
            type: 'meta',
            riskScore,
            totalDeps: deps.length,
            vulnerableCount,
          };
          controller.enqueue(encoder.encode(JSON.stringify(meta) + '\n'));

          // Step 4: Process each vulnerable dependency with Groq
          for (const result of osvResults) {
            if (result.vulns.length === 0) continue;

            for (const vuln of result.vulns) {
              const systemPrompt = 'You are a Node.js security engineer. You respond ONLY with valid JSON. No markdown, no backticks, no explanation outside the JSON object.';
              const userPrompt = `Analyze this vulnerability and return ONLY this JSON structure:
{
  "what": "one sentence describing what is broken in the code",
  "severity": "one of: Low | Medium | High | Critical",
  "impact": "one sentence on real-world impact for a typical web app",
  "fix": "exact action to fix: version to bump to, or 'No fix available'"
}

Package: ${result.dep.name}@${result.dep.version}
OSV Data: ${JSON.stringify(vuln, null, 2)}`;

              const groqStream = await groq.chat.completions.create({
                messages: [
                  { role: 'system', content: systemPrompt },
                  { role: 'user', content: userPrompt },
                ],
                model: 'llama3-8b-8192',
                stream: true,
              });

              let groqResponse = '';
              for await (const chunk of groqStream) {
                const content = chunk.choices[0]?.delta?.content || '';
                groqResponse += content;
              }

              // Parse Groq response
              let groqData;
              try {
                groqData = JSON.parse(groqResponse);
              } catch {
                groqData = {
                  what: 'Unable to parse AI response',
                  severity: 'Medium',
                  impact: 'Unknown',
                  fix: 'No fix available',
                };
              }

              // Emit vuln object
              const vulnData = {
                type: 'vuln',
                package: result.dep.name,
                version: result.dep.version,
                osvId: vuln.id,
                what: groqData.what || 'Unable to parse AI response',
                impact: groqData.impact || 'Unknown',
                severity: groqData.severity || 'Medium',
                fix: groqData.fix || 'No fix available',
              };
              controller.enqueue(encoder.encode(JSON.stringify(vulnData) + '\n'));
            }
          }

          controller.terminate();
        } catch (error) {
          controller.error(error);
        }
      },
    });

    return new Response(stream.readable, {
      headers: {
        'Content-Type': 'application/x-ndjson',
        'Transfer-Encoding': 'chunked',
      },
    });
  } catch (error) {
    return new Response(error instanceof Error ? error.message : 'Internal server error', { status: 500 });
  }
}