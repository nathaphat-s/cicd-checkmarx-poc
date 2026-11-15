"use client";

import { useEffect, useState } from "react";

// ✅ SECURE version of the same frontend page

// Only relative paths inside our own site are allowed as "next" (blocks open redirect)
function safeNext(next: string | null): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  return next;
}

export default function WelcomeClient() {
  const [name, setName] = useState("guest");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    // ✅ Stored as plain text in state; React escapes it when rendering (no innerHTML)
    setName(params.get("name") ?? "guest");
    // ✅ No postMessage listener: this page does not need cross-window messages.
    //    If it did: check e.origin against an allow-list and treat e.data as data, never eval it.
  }, []);

  const goNext = () => {
    const next = safeNext(new URLSearchParams(window.location.search).get("next"));
    window.location.assign(next);
  };

  return (
    <main>
      <h1>Welcome</h1>
      <div>สวัสดี {name}</div>
      <button onClick={goNext}>ไปต่อ</button>
    </main>
  );
}
