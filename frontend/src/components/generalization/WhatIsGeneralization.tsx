import "./WhatIsGeneralization.css";

export default function WhatIsGeneralization() {
  return (
    <div className="what-is-generalization">
      <div className="what-is-generalization__pair">
        <div className="what-is-generalization__item">
          <span className="what-is-generalization__label">Training</span>
          <p>The model learns from the development capture.</p>
        </div>
        <div className="what-is-generalization__item">
          <span className="what-is-generalization__label">Generalization</span>
          <p>
            We take that already-trained model and expose it to different capture days containing
            different traffic/attack conditions.
          </p>
        </div>
      </div>
      <p className="what-is-generalization__question">
        The question is: <strong>"Does the learned behaviour transfer beyond the original development
        capture?"</strong>
      </p>
    </div>
  );
}
