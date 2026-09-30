/**
 * Minimal hand-authored icon set (no external icon library dependency).
 * All icons: 20x20 viewBox, stroke = currentColor, 1.6 stroke width.
 */
import type { SVGProps } from "react";

const base: SVGProps<SVGSVGElement> = {
  viewBox: "0 0 20 20",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  width: 18,
  height: 18,
};

export const IconOverview = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <rect x="2.5" y="2.5" width="6" height="6" rx="1.2" />
    <rect x="11.5" y="2.5" width="6" height="6" rx="1.2" />
    <rect x="2.5" y="11.5" width="6" height="6" rx="1.2" />
    <rect x="11.5" y="11.5" width="6" height="6" rx="1.2" />
  </svg>
);

export const IconNetwork = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="10" cy="4" r="2" />
    <circle cx="4" cy="15" r="2" />
    <circle cx="16" cy="15" r="2" />
    <path d="M10 6v4M10 10l-4.5 3.5M10 10l4.5 3.5" />
  </svg>
);

export const IconForecast = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M2.5 14.5l4-5 3 2.5 4-5.5 4 3.5" />
    <path d="M13.5 6.5h4v4" />
  </svg>
);

export const IconAttack = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M10 2.5l7 3.2v4.3c0 4-3 7.2-7 7.5-4-.3-7-3.5-7-7.5V5.7L10 2.5z" />
    <path d="M10 7v3.6M10 13.2h.01" />
  </svg>
);

export const IconExplain = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="10" cy="10" r="7" />
    <path d="M10 13v.01M10 10.5c0-1.4 2-1.3 2-3a2 2 0 10-4 0" />
  </svg>
);

export const IconMitre = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M10 2.5l7 3v4.2c0 3.9-2.9 6.9-7 7.8-4.1-.9-7-3.9-7-7.8V5.5l7-3z" />
    <path d="M7 10l2 2 4-4.2" />
  </svg>
);

export const IconGeneralization = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="10" cy="10" r="7" />
    <path d="M3 10h14M10 3c2 2 3 4.5 3 7s-1 5-3 7c-2-2-3-4.5-3-7s1-5 3-7z" />
  </svg>
);

export const IconModels = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <rect x="3" y="4.5" width="14" height="11" rx="1.5" />
    <path d="M3 8.5h14M7.5 8.5V15.5" />
  </svg>
);

export const IconDatasets = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <ellipse cx="10" cy="5" rx="6.5" ry="2.3" />
    <path d="M3.5 5v5c0 1.3 2.9 2.3 6.5 2.3s6.5-1 6.5-2.3V5" />
    <path d="M3.5 10v5c0 1.3 2.9 2.3 6.5 2.3s6.5-1 6.5-2.3v-5" />
  </svg>
);

export const IconResearch = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="8.5" cy="8.5" r="5.5" />
    <path d="M16.5 16.5l-4-4" />
  </svg>
);

export const IconSettings = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="10" cy="10" r="2.6" />
    <path d="M10 2.8v2M10 15.2v2M17.2 10h-2M4.8 10h-2M15.1 4.9l-1.4 1.4M6.3 13.7l-1.4 1.4M15.1 15.1l-1.4-1.4M6.3 6.3L4.9 4.9" />
  </svg>
);

export const IconChevronRight = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M7.5 4.5l5.5 5.5-5.5 5.5" />
  </svg>
);

export const IconLayers = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M10 2.5l7 3.5-7 3.5-7-3.5 7-3.5z" />
    <path d="M3 10.2l7 3.5 7-3.5M3 13.8l7 3.5 7-3.5" />
  </svg>
);

export const IconClock = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <circle cx="10" cy="10" r="7" />
    <path d="M10 6v4l3 2" />
  </svg>
);

export const IconMitigation = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M10 2.5l7 3v4.2c0 3.9-2.9 6.9-7 7.8-4.1-.9-7-3.9-7-7.8V5.5l7-3z" />
    <path d="M6.5 10h7" />
  </svg>
);

export const IconVerification = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base} {...p}>
    <path d="M10 2.5l7 3v4.2c0 3.9-2.9 6.9-7 7.8-4.1-.9-7-3.9-7-7.8V5.5l7-3z" />
    <path d="M7 10l2 2 4-4.2" />
  </svg>
);
