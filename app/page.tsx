/**
 * Home page component for GN Security
 * Displays the application landing page with title and description
 * 
 * @returns JSX element with centered landing page content
 */
export default function Home() {
  return (
    <main className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">GN Security</h1>
        <p className="text-muted-foreground">Vulnerability Scanner</p>
      </div>
    </main>
  );
}
