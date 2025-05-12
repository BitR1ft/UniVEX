"""

Generates data-driven charts for embedding in security reports.
Uses matplotlib with the non-interactive Agg backend so it works
in headless/server environments without a display.

All public methods return base64-encoded PNG strings suitable for
embedding directly in HTML: ``<img src="data:image/png;base64,...">``.
"""
from __future__ import annotations

import base64
import io
import logging
from datetime import datetime
from typing import Dict, List, Optional

from app.reports.report_engine import Finding, Severity

logger = logging.getLogger(__name__)

# Severity color palette (matches UniVex UI)
_SEVERITY_COLORS: Dict[str, str] = {
    Severity.CRITICAL.value: "#DC2626",  # red-600
    Severity.HIGH.value:     "#EA580C",  # orange-600
    Severity.MEDIUM.value:   "#CA8A04",  # yellow-600
    Severity.LOW.value:      "#16A34A",  # green-600
    Severity.INFO.value:     "#2563EB",  # blue-600
}


def _to_base64(fig) -> str:  # type: ignore[return]
    """Serialize a matplotlib Figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


class ChartGenerator:
    """
    Generates charts for inclusion in security reports.

    All methods return base64-encoded PNG strings.
    If matplotlib is unavailable a warning is logged and an empty string
    is returned so the rest of report generation continues cleanly.
    """

    def __init__(self) -> None:
        self._mpl_available = False
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt  # noqa: F401
            self._mpl_available = True
        except ImportError:
            logger.warning(
                "matplotlib not installed — charts will be skipped. "
                "Install with: pip install matplotlib"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_severity_pie(self, findings: List[Finding]) -> str:
        """Pie chart: percentage of findings per severity level."""
        if not self._mpl_available or not findings:
            return ""
        try:
            import matplotlib.pyplot as plt

            counts = self._count_severity(findings)
            labels = [k for k, v in counts.items() if v > 0]
            sizes = [v for v in counts.values() if v > 0]
            colors = [_SEVERITY_COLORS[k] for k in labels]

            fig, ax = plt.subplots(figsize=(6, 5))
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                startangle=140,
                pctdistance=0.8,
            )
            for t in texts + autotexts:
                t.set_fontsize(10)
            ax.set_title("Finding Severity Distribution", fontsize=13, fontweight="bold")
            result = _to_base64(fig)
            plt.close(fig)
            return result
        except Exception as exc:
            logger.error("severity_pie chart failed: %s", exc)
            return ""

    def generate_severity_bar(self, findings: List[Finding]) -> str:
        """Horizontal bar chart: finding count per severity."""
        if not self._mpl_available or not findings:
            return ""
        try:
            import matplotlib.pyplot as plt

            counts = self._count_severity(findings)
            severities = list(counts.keys())
            values = list(counts.values())
            colors = [_SEVERITY_COLORS[s] for s in severities]

            fig, ax = plt.subplots(figsize=(7, 4))
            bars = ax.barh(severities, values, color=colors, edgecolor="white")
            ax.bar_label(bars, padding=3, fontsize=10)
            ax.set_xlabel("Number of Findings", fontsize=11)
            ax.set_title("Findings by Severity", fontsize=13, fontweight="bold")
            ax.invert_yaxis()
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            result = _to_base64(fig)
            plt.close(fig)
            return result
        except Exception as exc:
            logger.error("severity_bar chart failed: %s", exc)
            return ""

    def generate_cvss_histogram(self, findings: List[Finding]) -> str:
        """Histogram of CVSS scores across all findings."""
        if not self._mpl_available or not findings:
            return ""
        try:
            import matplotlib.pyplot as plt
            import numpy as np

            scores = [f.cvss_score for f in findings if f.cvss_score > 0]
            if not scores:
                return ""

            fig, ax = plt.subplots(figsize=(7, 4))
            ax.hist(scores, bins=10, range=(0, 10), color="#4F46E5", edgecolor="white", alpha=0.85)
            ax.axvline(np.mean(scores), color="#DC2626", linestyle="--", linewidth=1.5, label=f"Mean: {np.mean(scores):.1f}")
            ax.set_xlabel("CVSS Score", fontsize=11)
            ax.set_ylabel("Count", fontsize=11)
            ax.set_title("CVSS Score Distribution", fontsize=13, fontweight="bold")
            ax.legend(fontsize=10)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            result = _to_base64(fig)
            plt.close(fig)
            return result
        except Exception as exc:
            logger.error("cvss_histogram chart failed: %s", exc)
            return ""

    def generate_attack_timeline(
        self,
        findings: List[Finding],
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> str:
        """Timeline chart of findings discovered over time."""
        if not self._mpl_available or not findings:
            return ""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates

            dated = [f for f in findings if f.discovered_at]
            if not dated:
                return ""

            dates = sorted(f.discovered_at for f in dated)
            sev_colors = [_SEVERITY_COLORS.get(f.severity.value, "#6B7280") for f in sorted(dated, key=lambda x: x.discovered_at)]

            fig, ax = plt.subplots(figsize=(9, 4))
            for i, (d, c) in enumerate(zip(dates, sev_colors)):
                ax.scatter(d, i, color=c, s=60, zorder=3)
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
            plt.xticks(rotation=30, ha="right", fontsize=9)
            ax.set_title("Attack / Discovery Timeline", fontsize=13, fontweight="bold")
            ax.set_yticks([])
            ax.spines["left"].set_visible(False)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.grid(axis="x", linestyle="--", alpha=0.4)
            result = _to_base64(fig)
            plt.close(fig)
            return result
        except Exception as exc:
            logger.error("attack_timeline chart failed: %s", exc)
            return ""

    def generate_risk_heatmap(self, findings: List[Finding]) -> str:
        """
        Risk heatmap: Severity × Likelihood matrix.

        Cell colour intensity reflects how many findings fall in that cell.
        """
        if not self._mpl_available or not findings:
            return ""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.colors as mcolors
            import numpy as np

            severities = [s.value for s in Severity]
            likelihoods = ["low", "medium", "high"]

            # Build matrix
            matrix = np.zeros((len(severities), len(likelihoods)), dtype=int)
            sev_idx = {s: i for i, s in enumerate(severities)}
            lik_idx = {lk: i for i, lk in enumerate(likelihoods)}
            for f in findings:
                si = sev_idx.get(f.severity.value, 4)
                li = lik_idx.get(f.likelihood, 1)
                matrix[si, li] += 1

            fig, ax = plt.subplots(figsize=(7, 5))
            cmap = mcolors.LinearSegmentedColormap.from_list(
                "risk", ["#F0FDF4", "#FEF2F2", "#7F1D1D"]
            )
            im = ax.imshow(matrix, cmap=cmap, aspect="auto")
            ax.set_xticks(range(len(likelihoods)))
            ax.set_xticklabels([lk.capitalize() for lk in likelihoods], fontsize=11)
            ax.set_yticks(range(len(severities)))
            ax.set_yticklabels([s.capitalize() for s in severities], fontsize=11)
            ax.set_xlabel("Likelihood", fontsize=12)
            ax.set_ylabel("Severity", fontsize=12)
            ax.set_title("Risk Heatmap (Severity × Likelihood)", fontsize=13, fontweight="bold")
            for i in range(len(severities)):
                for j in range(len(likelihoods)):
                    val = matrix[i, j]
                    ax.text(j, i, str(val), ha="center", va="center",
                            fontsize=12, color="black" if val < matrix.max() * 0.7 else "white")
            fig.colorbar(im, ax=ax, label="Finding Count")
            result = _to_base64(fig)
            plt.close(fig)
            return result
        except Exception as exc:
            logger.error("risk_heatmap chart failed: %s", exc)
            return ""

    def generate_all(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Generate all standard charts and return as a dict of base64 strings.

        Returns:
            dict with keys: severity_pie, severity_bar, cvss_histogram, risk_heatmap
        """
        return {
            "severity_pie": self.generate_severity_pie(findings),
            "severity_bar": self.generate_severity_bar(findings),
            "cvss_histogram": self.generate_cvss_histogram(findings),
            "risk_heatmap": self.generate_risk_heatmap(findings),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_severity(findings: List[Finding]) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return counts
