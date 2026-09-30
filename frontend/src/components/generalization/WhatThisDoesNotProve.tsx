import StatusBadge from "../ui/StatusBadge";
import "./WhatThisDoesNotProve.css";

interface WhatThisDoesNotProveProps {
  notProven: string[];
  doesProvide: string[];
}

export default function WhatThisDoesNotProve({ notProven, doesProvide }: WhatThisDoesNotProveProps) {
  return (
    <div className="what-this-does-not-prove">
      <div className="what-this-does-not-prove__col">
        <StatusBadge label="Does NOT Prove" tone="danger" />
        <ul>
          {notProven.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
      <div className="what-this-does-not-prove__col">
        <StatusBadge label="Does Provide" tone="success" />
        <ul>
          {doesProvide.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
