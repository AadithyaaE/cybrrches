import type { ReactNode } from "react";
import "./SectionHeader.css";

interface SectionHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
}

export default function SectionHeader({ title, description, actions }: SectionHeaderProps) {
  return (
    <div className="section-header">
      <div className="section-header__text">
        <h1 className="section-header__title">{title}</h1>
        {description && <p className="section-header__description">{description}</p>}
      </div>
      {actions && <div className="section-header__actions">{actions}</div>}
    </div>
  );
}
