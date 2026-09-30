import { useLocation } from "react-router-dom";
import { navGroups } from "../../routes/navConfig";
import "./TopHeader.css";

const pathToLabel = new Map(
  navGroups.flatMap((group) => group.items.map((item) => [item.path, item.label] as const))
);

export default function TopHeader() {
  const location = useLocation();
  const currentLabel = pathToLabel.get(location.pathname) ?? "CyberChess";

  return (
    <header className="top-header">
      <div className="top-header__breadcrumb">
        <span className="top-header__breadcrumb-root">CyberChess</span>
        <span className="top-header__breadcrumb-sep">/</span>
        <span className="top-header__breadcrumb-current">{currentLabel}</span>
      </div>

      <div className="top-header__right">
        <span
          className="top-header__mode"
          title="This interface reads pre-computed research artifacts only; it does not control or monitor a live network."
        >
          <span className="top-header__mode-dot" aria-hidden="true" />
          <span className="top-header__mode-label">OFFLINE RESEARCH</span>
        </span>
      </div>
    </header>
  );
}
