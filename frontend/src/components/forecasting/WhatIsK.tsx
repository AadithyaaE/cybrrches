import "./WhatIsK.css";

const K_MEANINGS = [
  { k: "K=1", text: "The model forecasts one second ahead." },
  { k: "K=2", text: "The model forecasts two seconds ahead." },
  { k: "K=3", text: "The model forecasts three seconds ahead." },
  { k: "K=5", text: "The model forecasts five seconds ahead." },
];

export default function WhatIsK() {
  return (
    <div className="what-is-k">
      <div className="what-is-k__grid">
        {K_MEANINGS.map((item) => (
          <div className="what-is-k__item" key={item.k}>
            <span className="what-is-k__k">{item.k}</span>
            <span className="what-is-k__text">{item.text}</span>
          </div>
        ))}
      </div>
      <p className="what-is-k__note">
        K=1 is a direct one-step forecast from real observed history. K=2, K=3 and K=5 are{" "}
        <strong>recursive / free-running forecasts</strong>: after the first step, the frozen LSTM World
        Model feeds its own previous prediction back in as if it were the true next state, rather than
        being given the real ground truth. No retraining or fine-tuning happens for these longer horizons -
        it is the same frozen model, run forward multiple times.
      </p>
    </div>
  );
}
