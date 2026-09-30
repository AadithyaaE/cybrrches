import type { ReactNode } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import EmptyState from "../components/ui/EmptyState";

interface PlaceholderPageProps {
  title: string;
  description: string;
  icon?: ReactNode;
  emptyTitle: string;
  emptyDescription: string;
}

export default function PlaceholderPage({ title, description, icon, emptyTitle, emptyDescription }: PlaceholderPageProps) {
  return (
    <div>
      <SectionHeader title={title} description={description} />
      <EmptyState icon={icon} title={emptyTitle} description={emptyDescription} />
    </div>
  );
}
