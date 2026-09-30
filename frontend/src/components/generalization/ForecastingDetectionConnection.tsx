import "./ForecastingDetectionConnection.css";

export default function ForecastingDetectionConnection() {
  return (
    <div className="forecasting-detection-connection">
      <div className="forecasting-detection-connection__pair">
        <div className="forecasting-detection-connection__item">
          <span className="forecasting-detection-connection__label">Oracle (Wed-21-02-2018)</span>
          <span className="forecasting-detection-connection__value">ROC-AUC = 1.0</span>
          <span className="forecasting-detection-connection__sub">Classifier receives the actual future state.</span>
        </div>
        <div className="forecasting-detection-connection__item">
          <span className="forecasting-detection-connection__label">Full Pipeline (Wed-21-02-2018)</span>
          <span className="forecasting-detection-connection__value">ROC-AUC = 0.799</span>
          <span className="forecasting-detection-connection__sub">Classifier receives the LSTM-predicted future state.</span>
        </div>
      </div>
      <p className="forecasting-detection-connection__explain">
        The oracle classifier receives the actual future state, while the full pipeline uses the
        LSTM-predicted future state. On this day, the gap between the two (1.0 vs 0.799) is evidence that
        forecasting error can reduce downstream attack-detection performance - when the World Model's
        forecast deviates from reality, the classifier built on that forecast performs worse than it would
        on perfect information.
      </p>
      <p className="forecasting-detection-connection__caveat">
        This does not prove causality beyond this evaluation: it is one diagnostic comparison, on one
        external day, for one classifier. It shows that forecasting accuracy and downstream detection
        accuracy are connected in this specific case, not a general law about how much any given forecasting
        error will degrade detection.
      </p>
    </div>
  );
}
