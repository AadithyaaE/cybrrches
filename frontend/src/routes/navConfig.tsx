import type { NavGroup } from "../types/nav";
import {
  IconOverview,
  IconNetwork,
  IconForecast,
  IconAttack,
  IconExplain,
  IconMitre,
  IconGeneralization,
  IconModels,
  IconDatasets,
  IconResearch,
  IconSettings,
  IconMitigation,
  IconVerification,
} from "../components/ui/icons";

export const navGroups: NavGroup[] = [
  {
    items: [
      { label: "Overview", path: "/overview", icon: <IconOverview /> },
      { label: "End-to-End Demo", path: "/demo", icon: <IconResearch /> },
    ],
  },
  {
    title: "Analysis",
    items: [
      { label: "Network State", path: "/network-state", icon: <IconNetwork /> },
      { label: "Forecasting", path: "/forecasting", icon: <IconForecast /> },
      { label: "Attack Analysis", path: "/attack-analysis", icon: <IconAttack /> },
      { label: "Explainability", path: "/explainability", icon: <IconExplain /> },
      { label: "MITRE ATT&CK", path: "/mitre", icon: <IconMitre /> },
      { label: "Generalization", path: "/generalization", icon: <IconGeneralization /> },
      { label: "Mitigation", path: "/mitigation", icon: <IconMitigation /> },
      { label: "Verification", path: "/verification", icon: <IconVerification /> },
    ],
  },
  {
    title: "Platform",
    items: [
      { label: "Models & Metrics", path: "/models", icon: <IconModels /> },
      { label: "Datasets", path: "/datasets", icon: <IconDatasets /> },
      { label: "Research Pipeline", path: "/research", icon: <IconResearch /> },
    ],
  },
  {
    title: "System",
    items: [{ label: "Settings", path: "/settings", icon: <IconSettings /> }],
  },
];
