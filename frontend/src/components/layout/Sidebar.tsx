import { NavLink } from "react-router-dom";
import { navGroups } from "../../routes/navConfig";
import "./Sidebar.css";

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <div className="sidebar__brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M12 3l8 3.6v5c0 4.7-3.4 8.6-8 9.4-4.6-.8-8-4.7-8-9.4v-5L12 3z" />
            <path d="M9 12l2 2 4-4.4" />
          </svg>
        </div>
        <div className="sidebar__brand-text">
          <span className="sidebar__brand-name">CyberChess</span>
          <span className="sidebar__brand-tagline">Anticipate. Protect.</span>
        </div>
      </div>

      <nav className="sidebar__nav" aria-label="Primary">
        {navGroups.map((group, idx) => (
          <div className="sidebar__group" key={group.title ?? `group-${idx}`}>
            {group.title && <div className="sidebar__group-title">{group.title}</div>}
            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => "sidebar__link" + (isActive ? " sidebar__link--active" : "")}
              >
                <span className="sidebar__link-icon">{item.icon}</span>
                <span className="sidebar__link-label">{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar__status">
        <div className="sidebar__status-row">
          <span className="sidebar__status-dot" aria-hidden="true" />
          <span className="sidebar__status-label">OFFLINE RESEARCH</span>
        </div>
        <div className="sidebar__status-sub">Features 1-16 Complete</div>
      </div>
    </aside>
  );
}
