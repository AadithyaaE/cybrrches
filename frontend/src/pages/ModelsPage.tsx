import PlaceholderPage from "./PlaceholderPage";
import { IconModels } from "../components/ui/icons";

export default function ModelsPage() {
  return (
    <PlaceholderPage
      title="Models & Metrics"
      description="Frozen model inventory: Logistic Regression and Random Forest baselines, the LSTM World Model, and the next-state attack classifier."
      icon={<IconModels />}
      emptyTitle="No model metrics loaded"
      emptyDescription="Checkpoint metadata, training configuration, and validation metrics will appear here once connected to the results/ artifacts."
    />
  );
}
