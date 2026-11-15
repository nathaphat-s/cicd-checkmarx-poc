"use client";

import { useEffect, useRef } from "react";

// ⚠️ INTENTIONALLY VULNERABLE FRONTEND (runs in the user's browser)
export default function WelcomeClient() {
  const greeting = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);

    // ⚠️ DOM XSS (CWE-79): URL value written into the page as raw HTML
    // Try: /welcome?name=<img src=x onerror=alert(document.cookie)>
    const name = params.get("name") ?? "guest";
    if (greeting.current) greeting.current.innerHTML = "สวัสดี " + name;

    // ⚠️ Code injection via postMessage (CWE-94): any website that embeds or opens
    // this page can send code, and we run it without checking who sent it
    const onMessage = (e: MessageEvent) => {
      eval(e.data);
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  // ⚠️ Open redirect (CWE-601): "next" can be any website, e.g. a phishing page
  // Try: /welcome?next=https://evil.example.com
  const goNext = () => {
    const next = new URLSearchParams(window.location.search).get("next") ?? "/";
    window.location.href = next;
  };

  return (
    <main>
      <h1>Welcome</h1>
      <div ref={greeting} />
      <button onClick={goNext}>ไปต่อ</button>
    </main>
  );
}
