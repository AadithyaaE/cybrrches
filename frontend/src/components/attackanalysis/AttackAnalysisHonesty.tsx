import "./AttackAnalysisHonesty.css";

const HONESTY_NOTES = [
  "This is a frozen offline evaluation.",
  "It is not a live IDS (intrusion detection system).",
  "The current test split cannot estimate attack recall because it contains no attack-positive sequences.",
  "Do not claim universal attack detection.",
  "Do not claim that increasing K automatically means better forecasting or detection.",
];

export default function AttackAnalysisHonesty() {
  return (
    <ul className="attack-analysis-honesty__list">
      {HONESTY_NOTES.map((note) => (
        <li key={note} className="attack-analysis-honesty__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
