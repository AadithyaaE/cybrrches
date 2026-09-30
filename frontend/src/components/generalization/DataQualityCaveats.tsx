import "./DataQualityCaveats.css";

interface DataQualityCaveatsProps {
  caveats: string[];
}

export default function DataQualityCaveats({ caveats }: DataQualityCaveatsProps) {
  return (
    <ul className="data-quality-caveats__list">
      {caveats.map((note) => (
        <li key={note} className="data-quality-caveats__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
