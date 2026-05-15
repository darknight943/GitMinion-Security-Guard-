/**
 * Represents a dependency extracted from package.json
 */
export interface Dependency {
  /** Package name */
  name: string;
  /** Original version string (may include prefixes like ^, ~, >=) */
  version: string;
  /** Whether this is a production or development dependency */
  type: 'dependencies' | 'devDependencies';
}

/**
 * Default package.json placeholder for demonstration purposes.
 * Uses create-react-app template from 2021 with react-scripts 4.0.3,
 * which has known CVEs for testing the vulnerability scanner.
 */
export const DEFAULT_PACKAGE_JSON = `{
  "name": "my-app",
  "version": "0.1.0",
  "dependencies": {
    "react": "17.0.2",
    "react-dom": "17.0.2",
    "react-scripts": "4.0.3",
    "web-vitals": "1.1.2"
  },
  "devDependencies": {
    "eslint": "7.11.0",
    "@testing-library/react": "11.1.0"
  }
}`;

/**
 * Parses a package.json string and extracts all dependencies.
 * 
 * @param rawJson - The raw package.json content as a string
 * @returns Array of Dependency objects containing name, version, and type
 * @throws {Error} "Invalid package.json" if the JSON is malformed
 * @throws {Error} "No dependencies found" if both dependencies and devDependencies are empty/missing
 * 
 * @example
 * const deps = parseDependencies('{"dependencies": {"react": "17.0.2"}}');
 * // Returns: [{ name: "react", version: "17.0.2", type: "dependencies" }]
 */
export function parseDependencies(rawJson: string): Dependency[] {
  let parsed: any;
  
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    throw new Error("Invalid package.json");
  }

  const dependencies: Dependency[] = [];
  const deps = parsed.dependencies || {};
  const devDeps = parsed.devDependencies || {};

  if (Object.keys(deps).length === 0 && Object.keys(devDeps).length === 0) {
    throw new Error("No dependencies found");
  }

  for (const [name, version] of Object.entries(deps)) {
    dependencies.push({
      name,
      version: String(version),
      type: 'dependencies',
    });
  }

  for (const [name, version] of Object.entries(devDeps)) {
    dependencies.push({
      name,
      version: String(version),
      type: 'devDependencies',
    });
  }

  return dependencies;
}

/**
 * Removes semantic versioning prefixes (^, ~, >=, etc.) from a version string.
 * Useful for querying vulnerability databases that require clean version numbers.
 * 
 * @param version - The version string with potential prefixes (e.g., "^17.0.2")
 * @returns The version string without prefixes (e.g., "17.0.2")
 * 
 * @example
 * stripVersionPrefix("^17.0.2") // Returns "17.0.2"
 * stripVersionPrefix("~1.1.2") // Returns "1.1.2"
 * stripVersionPrefix(">=2.0.0") // Returns "2.0.0"
 */
export function stripVersionPrefix(version: string): string {
  return version.replace(/^[^0-9]/, '');
}