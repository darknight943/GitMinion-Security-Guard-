/**
 * OSV (Open Source Vulnerabilities) Integration
 * 
 * This module provides functions to interact with the Google OSV API
 * for querying vulnerability databases. It will include:
 * - Query functions for package vulnerabilities
 * - Response parsing and normalization
 * - Error handling for API failures
 * - Rate limiting and caching strategies
 * 
 * @see https://osv.dev
 */

import { Dependency } from './parser';

/**
 * Represents a vulnerability from the OSV database
 */
export interface Vulnerability {
  /** Unique identifier for the vulnerability (e.g., CVE-2021-12345) */
  id: string;
  /** Summary description of the vulnerability */
  summary: string;
  /** Severity information if available */
  severity?: Array<{
    type: string;
    score: string;
  }>;
  /** Affected package versions */
  affected?: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    versions: string[];
  }>;
}

/**
 * Result from OSV query mapped to a dependency
 */
export interface OSVResult {
  /** The dependency that was queried */
  dep: Dependency;
  /** Vulnerabilities found for this dependency (empty array if none) */
  vulns: Vulnerability[];
}

/**
 * Query the OSV API for vulnerabilities in batch
 * 
 * @param deps - Array of dependencies to query
 * @returns Array of OSVResults with dependencies and their vulnerabilities
 * @throws {Error} "OSV API unavailable" if the fetch fails
 * 
 * @example
 * const results = await queryOSV([
 *   { name: "react", version: "17.0.2", type: "dependencies" }
 * ]);
 */
export async function queryOSV(deps: Dependency[]): Promise<OSVResult[]> {
  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        queries: deps.map((d) => ({
          package: { name: d.name, ecosystem: 'npm' },
          version: d.version,
        })),
      }),
    });

    if (!response.ok) {
      throw new Error('OSV API unavailable');
    }

    const data = await response.json();
    
    // Map results back to their dependencies by index
    return deps.map((dep, index) => ({
      dep,
      vulns: data.results?.[index]?.vulns || [],
    }));
  } catch (error) {
    if (error instanceof Error && error.message === 'OSV API unavailable') {
      throw error;
    }
    throw new Error('OSV API unavailable');
  }
}