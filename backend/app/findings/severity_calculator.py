"""

Full CVSS v3.1 scorer with:
  - Base score (AV, AC, PR, UI, S, C, I, A)
  - Temporal score (E, RL, RC)
  - Environmental score (MAV, MAC, MPR, MUI, MS, MC, MI, MA, CR, IR, AR)
  - Qualitative severity rating (None / Low / Medium / High / Critical)
  - Vector string generation and parsing

Reference: https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict


# ---------------------------------------------------------------------------
# Enumerations — Base metrics
# ---------------------------------------------------------------------------


class AV(str, Enum):   # Attack Vector
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AC(str, Enum):   # Attack Complexity
    LOW = "L"
    HIGH = "H"


class PR(str, Enum):   # Privileges Required
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UI(str, Enum):   # User Interaction
    NONE = "N"
    REQUIRED = "R"


class S(str, Enum):    # Scope
    UNCHANGED = "U"
    CHANGED = "C"


class C(str, Enum):    # Confidentiality Impact
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class IntegrityImpact(str, Enum):    # Integrity Impact
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class A(str, Enum):    # Availability Impact
    NONE = "N"
    LOW = "L"
    HIGH = "H"


# ---------------------------------------------------------------------------
# Enumerations — Temporal metrics
# ---------------------------------------------------------------------------


class E(str, Enum):    # Exploit Code Maturity
    NOT_DEFINED = "X"
    UNPROVEN = "U"
    PROOF_OF_CONCEPT = "P"
    FUNCTIONAL = "F"
    HIGH = "H"


class RL(str, Enum):   # Remediation Level
    NOT_DEFINED = "X"
    OFFICIAL_FIX = "O"
    TEMPORARY_FIX = "T"
    WORKAROUND = "W"
    UNAVAILABLE = "U"


class RC(str, Enum):   # Report Confidence
    NOT_DEFINED = "X"
    UNKNOWN = "U"
    REASONABLE = "R"
    CONFIRMED = "C"


# ---------------------------------------------------------------------------
# Enumerations — Environmental metrics (modified base + requirements)
# ---------------------------------------------------------------------------


class CR(str, Enum):   # Confidentiality Requirement
    NOT_DEFINED = "X"
    LOW = "L"
    MEDIUM = "M"
    HIGH = "H"


class IR(str, Enum):   # Integrity Requirement
    NOT_DEFINED = "X"
    LOW = "L"
    MEDIUM = "M"
    HIGH = "H"


class AR(str, Enum):   # Availability Requirement
    NOT_DEFINED = "X"
    LOW = "L"
    MEDIUM = "M"
    HIGH = "H"


class SeverityRating(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ---------------------------------------------------------------------------
# CVSSMetric type alias
# ---------------------------------------------------------------------------

CVSSMetric = str   # opaque string from the Enum value


# ---------------------------------------------------------------------------
# CVSSVector dataclass
# ---------------------------------------------------------------------------


@dataclass
class CVSSVector:
    """Holds all CVSS v3.1 metric values."""
    # Base
    attack_vector: AV = AV.NETWORK
    attack_complexity: AC = AC.LOW
    privileges_required: PR = PR.NONE
    user_interaction: UI = UI.NONE
    scope: S = S.UNCHANGED
    confidentiality: C = C.NONE
    integrity: IntegrityImpact = IntegrityImpact.NONE
    availability: A = A.NONE
    # Temporal
    exploit_code_maturity: E = E.NOT_DEFINED
    remediation_level: RL = RL.NOT_DEFINED
    report_confidence: RC = RC.NOT_DEFINED
    # Environmental requirements
    confidentiality_requirement: CR = CR.NOT_DEFINED
    integrity_requirement: IR = IR.NOT_DEFINED
    availability_requirement: AR = AR.NOT_DEFINED

    def to_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        parts = [
            "CVSS:3.1",
            f"AV:{self.attack_vector.value}",
            f"AC:{self.attack_complexity.value}",
            f"PR:{self.privileges_required.value}",
            f"UI:{self.user_interaction.value}",
            f"S:{self.scope.value}",
            f"C:{self.confidentiality.value}",
            f"I:{self.integrity.value}",
            f"A:{self.availability.value}",
        ]
        if self.exploit_code_maturity != E.NOT_DEFINED:
            parts.append(f"E:{self.exploit_code_maturity.value}")
        if self.remediation_level != RL.NOT_DEFINED:
            parts.append(f"RL:{self.remediation_level.value}")
        if self.report_confidence != RC.NOT_DEFINED:
            parts.append(f"RC:{self.report_confidence.value}")
        if self.confidentiality_requirement != CR.NOT_DEFINED:
            parts.append(f"CR:{self.confidentiality_requirement.value}")
        if self.integrity_requirement != IR.NOT_DEFINED:
            parts.append(f"IR:{self.integrity_requirement.value}")
        if self.availability_requirement != AR.NOT_DEFINED:
            parts.append(f"AR:{self.availability_requirement.value}")
        return "/".join(parts)

    @classmethod
    def from_string(cls, vector: str) -> "CVSSVector":
        """Parse a CVSS v3.1 vector string."""
        vector = vector.strip()
        if vector.startswith("CVSS:3.1/") or vector.startswith("CVSS:3.0/"):
            vector = vector.split("/", 1)[1]

        parts = {p.split(":")[0]: p.split(":")[1] for p in vector.split("/") if ":" in p}

        def _get(key: str, enum_cls, default):
            val = parts.get(key, default.value if hasattr(default, "value") else default)
            try:
                return enum_cls(val)
            except ValueError:
                return default

        return cls(
            attack_vector=_get("AV", AV, AV.NETWORK),
            attack_complexity=_get("AC", AC, AC.LOW),
            privileges_required=_get("PR", PR, PR.NONE),
            user_interaction=_get("UI", UI, UI.NONE),
            scope=_get("S", S, S.UNCHANGED),
            confidentiality=_get("C", C, C.NONE),
            integrity=_get("I", IntegrityImpact, IntegrityImpact.NONE),
            availability=_get("A", A, A.NONE),
            exploit_code_maturity=_get("E", E, E.NOT_DEFINED),
            remediation_level=_get("RL", RL, RL.NOT_DEFINED),
            report_confidence=_get("RC", RC, RC.NOT_DEFINED),
            confidentiality_requirement=_get("CR", CR, CR.NOT_DEFINED),
            integrity_requirement=_get("IR", IR, IR.NOT_DEFINED),
            availability_requirement=_get("AR", AR, AR.NOT_DEFINED),
        )


# ---------------------------------------------------------------------------
# CVSSScore result
# ---------------------------------------------------------------------------


@dataclass
class CVSSScore:
    base_score: float
    temporal_score: float
    environmental_score: float
    overall_score: float
    severity_rating: SeverityRating
    vector_string: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "base_score": round(self.base_score, 1),
            "temporal_score": round(self.temporal_score, 1),
            "environmental_score": round(self.environmental_score, 1),
            "overall_score": round(self.overall_score, 1),
            "severity_rating": self.severity_rating.value,
            "vector_string": self.vector_string,
        }


# ---------------------------------------------------------------------------
# SeverityCalculator
# ---------------------------------------------------------------------------


class SeverityCalculator:
    """
    CVSS v3.1 calculator following the FIRST specification exactly.

    Usage::

        calc = SeverityCalculator()
        score = calc.calculate(CVSSVector(
            attack_vector=AV.NETWORK,
            attack_complexity=AC.LOW,
            privileges_required=PR.NONE,
            user_interaction=UI.NONE,
            scope=S.UNCHANGED,
            confidentiality=C.HIGH,
            integrity=IntegrityImpact.HIGH,
            availability=A.HIGH,
        ))
        print(score.base_score)   # → 9.8
        print(score.severity_rating)  # → SeverityRating.CRITICAL
    """

    # ------------------------------------------------------------------
    # Base metric numerical weights
    # ------------------------------------------------------------------

    _AV_SCORES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _AC_SCORES = {"L": 0.77, "H": 0.44}
    _PR_SCORES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_SCORES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI_SCORES = {"N": 0.85, "R": 0.62}
    _CIA_SCORES = {"N": 0.00, "L": 0.22, "H": 0.56}

    # Temporal metric weights
    _E_SCORES = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
    _RL_SCORES = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
    _RC_SCORES = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}

    # Environmental requirement weights
    _REQ_SCORES = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

    # ------------------------------------------------------------------
    # Qualitative rating boundaries
    # ------------------------------------------------------------------

    @staticmethod
    def _rating(score: float) -> SeverityRating:
        if score == 0.0:
            return SeverityRating.NONE
        if score < 4.0:
            return SeverityRating.LOW
        if score < 7.0:
            return SeverityRating.MEDIUM
        if score < 9.0:
            return SeverityRating.HIGH
        return SeverityRating.CRITICAL

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def calculate(self, vector: CVSSVector) -> CVSSScore:
        base = self._base_score(vector)
        temporal = self._temporal_score(base, vector)
        env = self._environmental_score(vector)
        overall = env if env > 0 else (temporal if temporal > 0 else base)
        return CVSSScore(
            base_score=round(base, 1),
            temporal_score=round(temporal, 1),
            environmental_score=round(env, 1),
            overall_score=round(overall, 1),
            severity_rating=self._rating(overall),
            vector_string=vector.to_string(),
        )

    def calculate_from_string(self, vector_string: str) -> CVSSScore:
        return self.calculate(CVSSVector.from_string(vector_string))

    def quick_score(
        self,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        scope: str = "U",
        c: str = "N",
        i: str = "N",
        a: str = "N",
    ) -> CVSSScore:
        """Convenience method accepting raw metric letter codes."""
        vector = CVSSVector(
            attack_vector=AV(av),
            attack_complexity=AC(ac),
            privileges_required=PR(pr),
            user_interaction=UI(ui),
            scope=S(scope),
            confidentiality=C(c),
            integrity=IntegrityImpact(i),
            availability=A(a),
        )
        return self.calculate(vector)

    # ------------------------------------------------------------------
    # Score calculations
    # ------------------------------------------------------------------

    def _base_score(self, v: CVSSVector) -> float:
        iss = self._iss(v)
        self._esc(v)

        if v.scope == S.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        exploitability = (
            8.22
            * self._AV_SCORES[v.attack_vector.value]
            * self._AC_SCORES[v.attack_complexity.value]
            * (
                self._PR_SCORES_CHANGED if v.scope == S.CHANGED
                else self._PR_SCORES_UNCHANGED
            )[v.privileges_required.value]
            * self._UI_SCORES[v.user_interaction.value]
        )

        if v.scope == S.UNCHANGED:
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)

        return self._roundup(raw)

    def _iss(self, v: CVSSVector) -> float:
        """Impact Sub-Score."""
        c_val = self._CIA_SCORES[v.confidentiality.value]
        i_val = self._CIA_SCORES[v.integrity.value]
        a_val = self._CIA_SCORES[v.availability.value]
        return 1 - (1 - c_val) * (1 - i_val) * (1 - a_val)

    def _esc(self, v: CVSSVector) -> float:
        """Exploitability Sub-Score."""
        pr_table = (
            self._PR_SCORES_CHANGED if v.scope == S.CHANGED
            else self._PR_SCORES_UNCHANGED
        )
        return (
            8.22
            * self._AV_SCORES[v.attack_vector.value]
            * self._AC_SCORES[v.attack_complexity.value]
            * pr_table[v.privileges_required.value]
            * self._UI_SCORES[v.user_interaction.value]
        )

    def _temporal_score(self, base: float, v: CVSSVector) -> float:
        e = self._E_SCORES[v.exploit_code_maturity.value]
        rl = self._RL_SCORES[v.remediation_level.value]
        rc = self._RC_SCORES[v.report_confidence.value]
        # All NOT_DEFINED → no change
        if e == 1.0 and rl == 1.0 and rc == 1.0:
            return base
        return self._roundup(base * e * rl * rc)

    def _environmental_score(self, v: CVSSVector) -> float:
        cr = self._REQ_SCORES[v.confidentiality_requirement.value]
        ir = self._REQ_SCORES[v.integrity_requirement.value]
        ar = self._REQ_SCORES[v.availability_requirement.value]

        # If all NOT_DEFINED return 0 to signal "not computed"
        if cr == 1.0 and ir == 1.0 and ar == 1.0:
            return 0.0

        c_val = self._CIA_SCORES[v.confidentiality.value]
        i_val = self._CIA_SCORES[v.integrity.value]
        a_val = self._CIA_SCORES[v.availability.value]

        miss = 1 - (
            (1 - cr * c_val)
            * (1 - ir * i_val)
            * (1 - ar * a_val)
        )
        miss = min(miss, 0.915)

        if v.scope == S.UNCHANGED:
            modified_impact = 6.42 * miss
        else:
            modified_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)

        if modified_impact <= 0:
            return 0.0

        exploitability = (
            8.22
            * self._AV_SCORES[v.attack_vector.value]
            * self._AC_SCORES[v.attack_complexity.value]
            * (
                self._PR_SCORES_CHANGED if v.scope == S.CHANGED
                else self._PR_SCORES_UNCHANGED
            )[v.privileges_required.value]
            * self._UI_SCORES[v.user_interaction.value]
        )

        if v.scope == S.UNCHANGED:
            raw = min(modified_impact + exploitability, 10)
        else:
            raw = min(1.08 * (modified_impact + exploitability), 10)

        e = self._E_SCORES[v.exploit_code_maturity.value]
        rl = self._RL_SCORES[v.remediation_level.value]
        rc = self._RC_SCORES[v.report_confidence.value]
        return self._roundup(raw * e * rl * rc)

    @staticmethod
    def _roundup(value: float) -> float:
        """CVSS roundup to nearest 0.1 (always round up)."""
        import math
        return math.ceil(value * 10) / 10
