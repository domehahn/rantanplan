package report

import (
	"fmt"
	"strings"

	"github.com/rantanplan-ai/rantanplan/internal/compare"
	"github.com/rantanplan-ai/rantanplan/internal/model"
)

// FormatHTMLDashboard generates a self-contained, interactive HTML report with CSS/JS.
func FormatHTMLDashboard(score model.AssuranceScore, matrix *compare.DifferentialMatrix) string {
	var sb strings.Builder

	gradeColor := "#10b981" // green
	if score.Grade == "C" || score.Grade == "B" {
		gradeColor = "#f59e0b" // yellow
	} else if score.Grade == "F" {
		gradeColor = "#ef4444" // red
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Rantanplan Assurance Report — ` + score.Target + `</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    .title h1 { margin: 0; font-size: 1.8rem; letter-spacing: -0.025em; }
    .subtitle { color: var(--muted); font-size: 0.95rem; margin-top: 0.25rem; }
    .badge-grade {
      background: ` + gradeColor + `;
      color: #000;
      font-weight: 800;
      font-size: 2rem;
      padding: 0.5rem 1.5rem;
      border-radius: 0.5rem;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.5rem; }
    .card-title { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-bottom: 0.5rem; }
    .card-value { font-size: 2rem; font-weight: 700; color: var(--accent); }
    .metric-row { margin-bottom: 1rem; }
    .metric-header { display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 0.25rem; }
    .bar-bg { background: #334155; height: 8px; border-radius: 4px; overflow: hidden; }
    .bar-fill { background: var(--accent); height: 100%; transition: width 0.3s; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { color: var(--muted); background: #0f172a; font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">
        <h1>Rantanplan Scanner Assurance Report</h1>
        <div class="subtitle">Cognitive Chaos & Adversarial Mutation Testing • Target: <strong>` + score.Target + `</strong> (` + score.TargetVersion + `)</div>
      </div>
      <div class="badge-grade">` + score.Grade + `</div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-title">Overall Score</div>
        <div class="card-value">` + fmt.Sprintf("%.1f / 100", score.OverallScore) + `</div>
      </div>
      <div class="card">
        <div class="card-title">Recall</div>
        <div class="card-value">` + fmt.Sprintf("%.1f%%", score.Metrics.Recall) + `</div>
      </div>
      <div class="card">
        <div class="card-title">Precision</div>
        <div class="card-value">` + fmt.Sprintf("%.1f%%", score.Metrics.Precision) + `</div>
      </div>
      <div class="card">
        <div class="card-title">Semantic Robustness</div>
        <div class="card-value">` + fmt.Sprintf("%.1f%%", score.Metrics.SemanticRobustness) + `</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 2rem;">
      <div class="card-title" style="margin-bottom: 1.5rem;">Robustness Breakdown Across Mutation Dimensions</div>
`)

	metrics := []struct {
		name string
		val  float64
	}{
		{"Recall", score.Metrics.Recall},
		{"Precision", score.Metrics.Precision},
		{"Semantic Robustness", score.Metrics.SemanticRobustness},
		{"Structural Robustness", score.Metrics.StructuralRobustness},
		{"Cross-File Robustness", score.Metrics.CrossFileRobustness},
		{"Obfuscation Robustness", score.Metrics.ObfuscationRobustness},
		{"Negative-Context Safety", score.Metrics.NegativeContextSafety},
	}

	for _, m := range metrics {
		sb.WriteString(fmt.Sprintf(`
      <div class="metric-row">
        <div class="metric-header"><span>%s</span><span>%.1f%%</span></div>
        <div class="bar-bg"><div class="bar-fill" style="width: %.1f%%"></div></div>
      </div>
`, m.name, m.val, m.val))
	}

	sb.WriteString(`    </div>
`)

	if matrix != nil && len(matrix.Targets) > 0 {
		sb.WriteString(`
    <div class="card">
      <div class="card-title">Differential Target Benchmark Matrix</div>
      <table>
        <thead>
          <tr>
            <th>Metric Dimension</th>
`)
		for _, t := range matrix.Targets {
			sb.WriteString(fmt.Sprintf("            <th>%s</th>\n", t))
		}
		sb.WriteString(`          </tr>
        </thead>
        <tbody>
`)
		diffMetrics := []struct {
			name string
			get  func(s model.AssuranceScore) float64
		}{
			{"Recall", func(s model.AssuranceScore) float64 { return s.Metrics.Recall }},
			{"Precision", func(s model.AssuranceScore) float64 { return s.Metrics.Precision }},
			{"Semantic Evasion", func(s model.AssuranceScore) float64 { return s.Metrics.SemanticRobustness }},
			{"Structural Robustness", func(s model.AssuranceScore) float64 { return s.Metrics.StructuralRobustness }},
			{"Cross-File Robustness", func(s model.AssuranceScore) float64 { return s.Metrics.CrossFileRobustness }},
			{"Negative-Context Safety", func(s model.AssuranceScore) float64 { return s.Metrics.NegativeContextSafety }},
			{"Overall Assurance Score", func(s model.AssuranceScore) float64 { return s.OverallScore }},
		}

		for _, dm := range diffMetrics {
			sb.WriteString(fmt.Sprintf("          <tr><td><strong>%s</strong></td>", dm.name))
			for _, t := range matrix.Targets {
				val := dm.get(matrix.Scores[t])
				sb.WriteString(fmt.Sprintf("<td>%.1f%%</td>", val))
			}
			sb.WriteString("</tr>\n")
		}
		sb.WriteString(`        </tbody>
      </table>
    </div>
`)
	}

	sb.WriteString(`  </div>
</body>
</html>`)

	return sb.String()
}
