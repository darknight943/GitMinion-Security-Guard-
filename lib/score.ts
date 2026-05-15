/**
 * Vulnerability Scoring Module
 * 
 * This module provides functions to calculate and analyze
 * vulnerability scores based on multiple factors:
 * - CVSS scores
 * - AI-assisted risk assessment
 * - Project-specific context
 * - Dependency usage patterns
 * 
 * Functions will include:
 * - scoreVulnerability(): Calculate overall risk score
 * - normalizeScore(): Normalize scores to standard scale
 * - aggregateScores(): Combine multiple vulnerability scores
 */

import { OSVResult, Vulnerability } from './osv';

/**
 * Severity levels for vulnerability classification
 */
type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Extracts the severity level from a vulnerability's severity array
 * 
 * @param vuln - The vulnerability to check
 * @returns The severity level or 'LOW' if not specified
 */
function getSeverityLevel(vuln: Vulnerability): SeverityLevel {
  if (!vuln.severity || vuln.severity.length === 0) {
    return 'LOW';
  }

  // Look for CVSS score (typically type: "CVSS_V3" or similar)
  const cvssSeverity = vuln.severity.find(s => s.type.includes('CVSS'));
  if (!cvssSeverity) {
    return 'LOW';
  }

  const score = parseFloat(cvssSeverity.score);
  if (isNaN(score)) {
    return 'LOW';
  }

  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/**
 * Calculates the overall risk score based on OSV query results
 * 
 * Formula:
 * - vulnerablePackages = count of deps with at least one vuln
 * - totalPackages = osvResults.length
 * - criticalCount = vulns with severity CRITICAL
 * - highCount = vulns with severity HIGH
 * - mediumCount = vulns with severity MEDIUM
 * 
 * score = (vulnerablePackages / totalPackages) * 60
 *       + criticalCount * 15
 *       + highCount * 8
 *       + mediumCount * 3
 * 
 * Score is capped at 100, floored at 0, and rounded to integer.
 * 
 * @param osvResults - Array of OSV results from vulnerability scan
 * @returns Risk score between 0 and 100
 * 
 * @example
 * const results = await queryOSV(deps);
 * const score = calculateRiskScore(results);
 * // Returns: 45
 */
export function calculateRiskScore(osvResults: OSVResult[]): number {
  if (osvResults.length === 0) {
    return 0;
  }

  const vulnerablePackages = osvResults.filter(r => r.vulns.length > 0).length;
  const totalPackages = osvResults.length;

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;

  for (const result of osvResults) {
    for (const vuln of result.vulns) {
      const level = getSeverityLevel(vuln);
      if (level === 'CRITICAL') criticalCount++;
      else if (level === 'HIGH') highCount++;
      else if (level === 'MEDIUM') mediumCount++;
    }
  }

  let score = (vulnerablePackages / totalPackages) * 60
            + criticalCount * 15
            + highCount * 8
            + mediumCount * 3;

  // Cap at 100, floor at 0, round to integer
  score = Math.max(0, Math.min(100, score));
  return Math.round(score);
}

/**
 * Gets the label and color for a given risk score
 * 
 * @param score - Risk score between 0 and 100
 * @returns Object with label and Tailwind CSS color class
 * 
 * @example
 * const { label, color } = getScoreLabel(45);
 * // Returns: { label: "Low Risk", color: "text-yellow-400" }
 */
export function getScoreLabel(score: number): { label: string; color: string } {
  if (score <= 25) {
    return { label: 'Safe', color: 'text-green-400' };
  }
  if (score <= 50) {
    return { label: 'Low Risk', color: 'text-yellow-400' };
  }
  if (score <= 75) {
    return { label: 'Medium Risk', color: 'text-orange-400' };
  }
  return { label: 'High Risk', color: 'text-red-500' };
}