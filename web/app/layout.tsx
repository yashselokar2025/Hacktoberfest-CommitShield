import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureVibeCoded — AI-Powered Git Security Gate",
  description:
    "SecureVibeCoded (svc) is a lightweight CLI that runs as a pre-commit hook, scanning staged commits for secret leaks and outdated dependencies using Gemma AI and logistic regression. Change-aware, explainable, and open-source.",
  keywords: [
    "git security",
    "secret scanning",
    "pre-commit hook",
    "Gemma AI",
    "devSecOps",
    "CLI tool",
    "open source",
  ],
  authors: [{ name: "Yash Selokar" }],
  openGraph: {
    title: "SecureVibeCoded — AI-Powered Git Security Gate",
    description:
      "Stop leaking secrets. Run svc install once, stay protected forever.",
    type: "website",
    url: "https://hacktoberfest-commit-shield-git-main-yash-selokars-projects.vercel.app",
  },
  twitter: {
    card: "summary_large_image",
    title: "SecureVibeCoded — AI-Powered Git Security Gate",
    description:
      "Open-source CLI pre-commit hook with Gemma AI. Zero noise. Only what changed.",
  },
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased noise-bg min-h-screen">
        {children}
      </body>
    </html>
  );
}
