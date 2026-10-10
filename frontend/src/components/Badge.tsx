import { statusPt } from "../i18n";

// Severity badges keep their English label (Critical/High/...), as these are
// standard AppSec terms used as severity labels. Scan-status badges show the
// PT-BR word while keeping the semantic class for color.
const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const GATE = new Set(["PASS", "FAIL", "WARNING"]);

function titleCase(v: string): string {
  return v.charAt(0) + v.slice(1).toLowerCase();
}

export function Badge({ value, kind }: { value: string; kind?: "status" | "severity" | "gate" }) {
  const upper = (value || "").toUpperCase();
  let text = value;

  if (kind === "status" || (!kind && !SEVERITIES.has(upper) && !GATE.has(upper))) {
    text = statusPt(upper);
  } else if (SEVERITIES.has(upper)) {
    text = titleCase(upper); // Critical, High, Medium, Low, Info
  } else {
    text = upper; // PASS / FAIL / WARNING
  }

  return (
    <span className={`badge ${upper}`} role="status" aria-label={text}>
      <span className="bdot" aria-hidden="true" />
      {text}
    </span>
  );
}
