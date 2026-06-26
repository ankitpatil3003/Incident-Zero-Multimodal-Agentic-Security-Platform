"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

interface NavItem {
  href: string;
  label: string;
  icon: string;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Dashboard", icon: "◉" },
  { href: "/upload", label: "New Scan", icon: "⬆" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <nav className="sidebar" aria-label="Main navigation">
      <div className="sidebar-header">
        <Link href="/" className="sidebar-logo">
          <span className="logo-icon">⬡</span>
          <span className="logo-text">Incident Zero</span>
        </Link>
      </div>

      <ul className="sidebar-nav">
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <li key={item.href}>
              <Link
                href={item.href}
                className={`sidebar-link${isActive ? " sidebar-link--active" : ""}`}
                aria-current={isActive ? "page" : undefined}
              >
                <span className="sidebar-link-icon" aria-hidden="true">
                  {item.icon}
                </span>
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>

      <div className="sidebar-footer">
        <span className="sidebar-version">v0.1.0</span>
      </div>
    </nav>
  );
}
