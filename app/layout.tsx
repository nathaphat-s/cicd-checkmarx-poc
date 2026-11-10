import type { ReactNode } from "react";

export const metadata = { title: "CI/CD Security POC" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="th">
      <body style={{ fontFamily: "system-ui, sans-serif", maxWidth: 720, margin: "40px auto", padding: "0 16px" }}>
        {children}
      </body>
    </html>
  );
}
