import type { Metadata } from "next";
import { Inter, Geist } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";

/**
 * Geist font configuration for the application
 * Variable font for consistent typography across the UI
 */
const geist = Geist({subsets:['latin'],variable:'--font-sans'});

/**
 * Inter font configuration for the application
 * Primary font for body text and content
 */
const inter = Inter({ subsets: ["latin"] });

/**
 * Metadata for the GN Security application
 * Used for SEO and browser display
 */
export const metadata: Metadata = {
  title: "GN Security",
  description: "Vulnerability Scanner",
};

/**
 * Root layout component for the Next.js application
 * Wraps all pages with consistent HTML structure, fonts, and dark mode
 * 
 * @param children - Child components/pages to render
 * @returns JSX element with HTML structure
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={cn("dark", "font-sans", geist.variable)}>
      <body className={inter.className}>{children}</body>
    </html>
  );
}
