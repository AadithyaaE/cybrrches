import PlaceholderPage from "./PlaceholderPage";
import { IconResearch } from "../components/ui/icons";

export default function ResearchPage() {
  return (
    <PlaceholderPage
      title="Research Pipeline"
      description="The full CyberChess research pipeline: dataset preparation, feature engineering, temporal modelling, forecasting, and generalization evaluation."
      icon={<IconResearch />}
      emptyTitle="Pipeline overview not yet connected"
      emptyDescription="A feature-by-feature summary of the completed research pipeline (Features 1-16) will be shown here once connected to the results/ directory."
    />
  );
}
