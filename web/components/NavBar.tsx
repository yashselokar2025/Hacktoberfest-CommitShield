"use client";

import { useState, useEffect } from "react";
import { Shield, Github, Menu, X } from "lucide-react";

const NAV_LINKS = [
  { href: "#why",        label: "Why" },
  { href: "#features",   label: "Features" },
  { href: "#playground", label: "Playground" },
  { href: "#social",     label: "Community" },
  { href: "#config",     label: "Config" },
];

export default function NavBar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 10);
    window.addEventListener("scroll", handler);
    return () => window.removeEventListener("scroll", handler);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? "bg-[#0a0a0f]/90 backdrop-blur border-b border-slate-800"
          : "bg-transparent"
      }`}
    >
      <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
        {/* Logo */}
        <a href="#" className="flex items-center gap-2 font-bold text-white hover:text-green-400 transition-colors">
          <Shield size={20} className="text-green-400" />
          <span>SecureVibeCoded</span>
          <span className="text-xs text-slate-500 font-normal hidden sm:block">v1.0.0</span>
        </a>

        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-6">
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              {link.label}
            </a>
          ))}
        </div>

        {/* Actions */}
        <div className="hidden md:flex items-center gap-3">
          <a
            href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white text-sm transition-all"
          >
            <Github size={14} />
            GitHub
          </a>
          <a
            href="#playground"
            className="px-3 py-1.5 rounded-lg bg-green-500 hover:bg-green-400 text-black font-semibold text-sm transition-all"
          >
            Try it →
          </a>
        </div>

        {/* Mobile menu toggle */}
        <button
          className="md:hidden text-slate-400 hover:text-white p-1"
          onClick={() => setOpen(!open)}
          aria-label="Toggle menu"
        >
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile drawer */}
      {open && (
        <div className="md:hidden bg-[#0a0a0f]/95 backdrop-blur border-b border-slate-800 px-4 pb-4">
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              onClick={() => setOpen(false)}
              className="block py-3 text-sm text-slate-400 hover:text-white border-b border-slate-800/50 transition-colors"
            >
              {link.label}
            </a>
          ))}
          <div className="flex gap-3 mt-4">
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield"
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 text-center py-2 rounded-lg border border-slate-700 text-slate-300 text-sm"
            >
              GitHub
            </a>
            <a
              href="#playground"
              onClick={() => setOpen(false)}
              className="flex-1 text-center py-2 rounded-lg bg-green-500 text-black font-semibold text-sm"
            >
              Try it →
            </a>
          </div>
        </div>
      )}
    </nav>
  );
}
