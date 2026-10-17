import { NextResponse } from "next/server";

export async function GET() {
  try {
    const res = await fetch(
      "https://api.github.com/repos/yashselokar2025/Hacktoberfest-CommitShield",
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "securevibecoded-web/1.0",
        },
        next: { revalidate: 300 }, // cache 5 min
      }
    );

    if (!res.ok) throw new Error(`GitHub API ${res.status}`);

    const data = await res.json();
    return NextResponse.json({
      stars: data.stargazers_count,
      forks: data.forks_count,
      open_issues: data.open_issues_count,
      watchers: data.watchers_count,
    });
  } catch {
    // Fallback so the page still renders
    return NextResponse.json({ stars: 0, forks: 0, open_issues: 0, watchers: 0 });
  }
}
