'use client';
import ExtendedButton from "./ExtendedButton";
import { IoIosSearch } from "react-icons/io";
import { CiSettings } from "react-icons/ci";
import Link from "next/link";
import { usePathname } from 'next/navigation';

export default function Nav({
  className = "",
}) {
  
  const navLinks = [
    { href: "/", label: "Home" },
    { href: "/categories", label: "Categories" },
    { href: "/archives", label: "Archives" },
    { href: "/tags", label: "Tags" }
  ];

  return (
    <nav className={`fixed top-0 left-0 w-full h-[135px] text-text flex items-center justify-center font-primary z-50 ${className}`}>
      <div id="nav-width-limiter" className="w-[1400px] h-full flex items-center justify-between">
        <Link href="/" prefetch={true}>
          <img 
            className="relative bottom-1"
            src="/light-logo.png" 
            height="135px" 
            width="135px" 
            alt="logo" 
          />
        </Link>
        <ul className="flex items-center justify-center">
          {navLinks.map((link) => (
            <li key={link.href} className="mx-4 text-lg">
              <Link 
                href={link.href}
                prefetch={true}
              >
                {link.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className="nav-buttons flex items-center justify-center gap-6">
          <ExtendedButton className="m-2">
            <IoIosSearch
              className="text-3xl"
            />
          </ExtendedButton>
          <ExtendedButton className="m-2">
            <CiSettings
              className="text-3xl"
            />
          </ExtendedButton>
        </div>
      </div>
    </nav>
  );
}