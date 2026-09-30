import "./ForecastingScopeNotes.css";

const SCOPE_NOTES = [
  "This is not live network forecasting.",
  "These are frozen research-model evaluation results.",
  "State forecasting predicts future network-state vectors, not a guaranteed future attack.",
  "Attack-progression probability is handled separately by the Attack Analysis feature.",
  "The model has not been retrained for this frontend page.",
];

export default function ForecastingScopeNotes() {
  return (
    <ul className="forecasting-scope-notes__list">
      {SCOPE_NOTES.map((note) => (
        <li key={note} className="forecasting-scope-notes__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
