import NavBar from "@/components/NavBar";
import Hero from "@/components/Hero";
import Comparison from "@/components/Comparison";
import AiLeakSolution from "@/components/AiLeakSolution";
import FeatureGrid from "@/components/FeatureGrid";
import ArchitectureSection from "@/components/ArchitectureSection";
import GemmaArchitecture from "@/components/GemmaArchitecture";
import JudgesPitchSection from "@/components/JudgesPitchSection";
import Playground from "@/components/Playground";
import SocialProof from "@/components/SocialProof";
import ConfigBuilder from "@/components/ConfigBuilder";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <NavBar />
      <main>
        {/* 1. Hero — animated terminal + install command */}
        <Hero />

        {/* 2. Why — before/after comparison */}
        <Comparison />

        {/* 3. AI Coding Leak Defense Vector */}
        <AiLeakSolution />

        {/* 4. Features — bento grid */}
        <FeatureGrid />

        {/* 5. Architecture & Live Logic Pipeline */}
        <ArchitectureSection />

        {/* 6. Google Gemma AI Architecture */}
        <GemmaArchitecture />

        {/* 7. Why This Project Wins (4 Pillars + Demo Script + FAQ) */}
        <JudgesPitchSection />

        {/* 8. Playground — interactive fake terminal */}
        <Playground />

        {/* 5. Social proof — GitHub stats + testimonials */}
        <SocialProof />

        {/* 6. Config builder */}
        <ConfigBuilder />
      </main>
      <Footer />
    </>
  );
}
