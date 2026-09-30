import PlaceholderPage from "./PlaceholderPage";
import { IconSettings } from "../components/ui/icons";

export default function SettingsPage() {
  return (
    <PlaceholderPage
      title="Settings"
      description="Application preferences and data-source configuration."
      icon={<IconSettings />}
      emptyTitle="No settings available yet"
      emptyDescription="Configuration options will be added once data integration begins."
    />
  );
}
