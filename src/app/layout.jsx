import Nav from "@/components/Nav";
import "./globals.css";

export const metadata = {
  title: "bi0s | Blog",
  description: "The official blog of team bi0s",
  keywords: "CTF, Writeup, Cyber, Blog",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body
        className={`antialiased`}
        suppressHydrationWarning={true}
      >
        <div id="bg"></div>
        <Nav />
        {children}
      </body>
    </html>
  );
}
