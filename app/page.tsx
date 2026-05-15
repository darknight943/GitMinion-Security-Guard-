/**
 * Home page component for DepSentry
 * Displays the main Scanner component for vulnerability scanning
 * 
 * @returns JSX element with Scanner component and footer
 */
import Scanner from '@/components/Scanner';

export default function Home() {
  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <Scanner />
      <footer className="mt-12 text-center text-sm text-muted-foreground">
        Powered by OSV.dev + Groq · Built for Activate Fellowship
      </footer>
    </div>
  );
}
