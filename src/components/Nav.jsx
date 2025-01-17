'use client';
import ExtendedButton from "./ExtendedButton";
import { IoIosSearch } from "react-icons/io";
import { CiSettings } from "react-icons/ci";
import Link from "next/link";
import { usePathname } from 'next/navigation';

export default function Nav({
  smallClass = "text-sm",
  mediumClass = "md:text-xl",
  largeClass = "lg:text-3xl",
  wrapperClass = "",
  wrapperStyle = {},
}) {
  
  const navLinks = [
    { href: "/", label: "Home" },
    { href: "/categories", label: "Categories" },
    { href: "/archive", label: "Archive" },
    { href: "/tags", label: "Tags" }
  ];

  return (
    <nav className="fixed w-full h-[100px] flex items-center justify-center">
      <div id="nav-width-limiter" className="w-[1400px] h-full flex items-center justify-around">
        <Link href="/" prefetch={true}>
          <img src="/light-logo.png" height="125px" width="125px" alt="logo" />
        </Link>
        <ul className="flex items-center justify-center">
          {navLinks.map((link) => (
            <li key={link.href} className="mx-4">
              <Link 
                href={link.href}
                prefetch={true}
              >
                {link.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className="nav-buttons flex items-center justify-center gap-4">
          <ExtendedButton>
            <IoIosSearch
              className="text-3xl"
            />
          </ExtendedButton>
          <ExtendedButton>
            <CiSettings
              className="text-3xl"
            />
          </ExtendedButton>
        </div>
      </div>
    </nav>
  );
}