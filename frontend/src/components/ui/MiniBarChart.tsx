import "./MiniBarChart.css";

export interface MiniBarChartSeries {
  label: string;
  color: string;
  values: Array<number | null>;
}

interface MiniBarChartProps {
  categories: string[];
  series: MiniBarChartSeries[];
  valueFormatter?: (value: number) => string;
  height?: number;
}

export default function MiniBarChart({ categories, series, valueFormatter, height = 140 }: MiniBarChartProps) {
  const allValues = series.flatMap((s) => s.values).filter((v): v is number => v !== null && Number.isFinite(v));
  const maxValue = allValues.length > 0 ? Math.max(...allValues) : 1;

  return (
    <div className="mini-bar-chart">
      {series.length > 1 && (
        <div className="mini-bar-chart__legend">
          {series.map((s) => (
            <span key={s.label} className="mini-bar-chart__legend-item">
              <span className="mini-bar-chart__legend-swatch" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
      <div className="mini-bar-chart__plot" style={{ height }}>
        {categories.map((category, i) => (
          <div className="mini-bar-chart__group" key={category}>
            <div className="mini-bar-chart__bars">
              {series.map((s) => {
                const value = s.values[i];
                if (value === null) {
                  return (
                    <div className="mini-bar-chart__bar-slot" key={s.label} title="Not available">
                      <span className="mini-bar-chart__bar-na">—</span>
                    </div>
                  );
                }
                const pct = maxValue > 0 ? Math.max((value / maxValue) * 100, 2) : 0;
                return (
                  <div className="mini-bar-chart__bar-slot" key={s.label}>
                    <span className="mini-bar-chart__bar-value">
                      {valueFormatter ? valueFormatter(value) : value.toFixed(2)}
                    </span>
                    <div
                      className="mini-bar-chart__bar"
                      style={{ height: `${pct}%`, background: s.color }}
                    />
                  </div>
                );
              })}
            </div>
            <span className="mini-bar-chart__category">{category}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
