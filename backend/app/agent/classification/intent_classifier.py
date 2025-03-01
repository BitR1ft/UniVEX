"""
Intent Classifier

Multi-label attack intent classifier that replaces the keyword-only
``AttackPathRouter`` logic.

Three classification modes (configurable via env var CLASSIFIER_MODE):
  keyword  — fast regex/keyword matching (legacy fallback, < 1ms)
  ml       — scikit-learn SVM multi-label classifier (~5ms, ≥85% accuracy)
  llm      — GPT-4 structured output (most accurate, ~500ms, uses API credit)
  hybrid   — ML + LLM with confidence merging (recommended for production)

Confidence scores
-----------------
Each category gets a probability 0-1.  Categories with probability ≥ the
``threshold`` (default 0.3) are returned in ranked order.

Training data
-------------
The classifier is trained from ``backend/data/intent_training_data.json``
(500+ labelled examples).  The model artefact is serialised to
``backend/data/classifier_model.pkl`` so it loads instantly on startup.

Multi-label support
-------------------
A single scenario can belong to multiple categories
(e.g. ``brute_force + privilege_escalation``).  All matching categories
are returned rather than just the first hit.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional


from .feature_extractor import FeatureExtractor, TECHNIQUE_KEYWORDS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
_TRAINING_DATA_PATH = _DATA_DIR / "intent_training_data.json"
_MODEL_PATH = _DATA_DIR / "classifier_model.pkl"

# ---------------------------------------------------------------------------
# Category list (must match AttackCategory enum values)
# ---------------------------------------------------------------------------

CATEGORIES = sorted(TECHNIQUE_KEYWORDS.keys())

# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------


class ClassificationResult:
    """Result of classifying an attack scenario."""

    def __init__(
        self,
        categories: List[str],
        scores: Dict[str, float],
        method: str,
        top_category: str,
    ):
        self.categories = categories       # all categories above threshold
        self.scores = scores               # {category: confidence 0-1}
        self.method = method               # "keyword" | "ml" | "llm" | "hybrid"
        self.top_category = top_category   # highest-scored category

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ClassificationResult(top={self.top_category}, "
            f"all={self.categories}, method={self.method})"
        )


# ===========================================================================
# Keyword classifier (legacy baseline)
# ===========================================================================


class KeywordClassifier:
    """Simple keyword-matching classifier (existing AttackPathRouter logic)."""

    _KEYWORDS: Dict[str, List[str]] = {
        cat: kws for cat, kws in TECHNIQUE_KEYWORDS.items()
    }

    def predict(
        self, text: str, threshold: float = 0.0
    ) -> ClassificationResult:
        lower = text.lower()
        scores: Dict[str, float] = {}
        for cat, kws in self._KEYWORDS.items():
            hits = sum(1 for kw in kws if kw in lower)
            scores[cat] = min(hits / max(len(kws), 1), 1.0)

        matched = [c for c, s in scores.items() if s > threshold]
        matched.sort(key=lambda c: scores[c], reverse=True)
        top = matched[0] if matched else "web_app_attack"
        return ClassificationResult(
            categories=matched or ["web_app_attack"],
            scores=scores,
            method="keyword",
            top_category=top,
        )


# ===========================================================================
# ML classifier (scikit-learn SVM + TF-IDF)
# ===========================================================================


class MLClassifier:
    """
    Multi-label SVM classifier trained on labelled attack descriptions.

    Uses a ``OneVsRestClassifier(LinearSVC)`` pipeline with TF-IDF + keyword
    features.  Calibrated via ``CalibratedClassifierCV`` for probability output.
    """

    def __init__(self):
        self._pipeline: Any = None
        self._extractor: Optional[FeatureExtractor] = None
        self._is_trained = False
        self._binarizer: Any = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, data_path: Path = _TRAINING_DATA_PATH) -> "MLClassifier":
        """Load training data, extract features, train SVM."""
        try:
            from sklearn.calibration import CalibratedClassifierCV
            from sklearn.multiclass import OneVsRestClassifier
            from sklearn.preprocessing import MultiLabelBinarizer
            from sklearn.svm import LinearSVC
        except ImportError as exc:
            raise ImportError(
                "scikit-learn is required for MLClassifier. "
                "Install it with: pip install scikit-learn"
            ) from exc

        logger.info("Loading training data from %s", data_path)
        with open(data_path) as fh:
            raw = json.load(fh)

        texts = [item["text"] for item in raw]
        labels = [item["labels"] for item in raw]

        self._binarizer = MultiLabelBinarizer(classes=CATEGORIES)
        y = self._binarizer.fit_transform(labels)

        self._extractor = FeatureExtractor(use_tfidf=True, use_sentence_transformers=False)
        X = self._extractor.fit_transform(texts)

        base_clf = LinearSVC(max_iter=2000, C=1.0)
        calibrated = CalibratedClassifierCV(base_clf, cv=3)
        self._pipeline = OneVsRestClassifier(calibrated)
        self._pipeline.fit(X, y)
        self._is_trained = True

        logger.info(
            "ML classifier trained on %d examples, %d categories",
            len(texts),
            len(CATEGORIES),
        )
        return self

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def save(self, model_path: Path = _MODEL_PATH) -> None:
        """Serialise trained model to disk."""
        with open(model_path, "wb") as fh:
            pickle.dump(
                {
                    "pipeline": self._pipeline,
                    "extractor": self._extractor,
                    "binarizer": self._binarizer,
                },
                fh,
            )
        logger.info("ML model saved to %s", model_path)

    @classmethod
    def load(cls, model_path: Path = _MODEL_PATH) -> "MLClassifier":
        """Load a previously trained model from disk."""
        instance = cls()
        with open(model_path, "rb") as fh:
            data = pickle.load(fh)
        instance._pipeline = data["pipeline"]
        instance._extractor = data["extractor"]
        instance._binarizer = data["binarizer"]
        instance._is_trained = True
        logger.info("ML model loaded from %s", model_path)
        return instance

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(
        self, text: str, threshold: float = 0.3
    ) -> ClassificationResult:
        if not self._is_trained:
            raise RuntimeError("Model is not trained. Call train() or load() first.")

        X = self._extractor.transform([text])
        # predict_proba returns shape (n_samples, n_classes)
        proba = self._pipeline.predict_proba(X)[0]

        scores = {cat: float(p) for cat, p in zip(CATEGORIES, proba)}
        matched = [c for c, s in scores.items() if s >= threshold]
        matched.sort(key=lambda c: scores[c], reverse=True)

        top = matched[0] if matched else max(scores, key=scores.get)  # type: ignore[arg-type]

        return ClassificationResult(
            categories=matched or [top],
            scores=scores,
            method="ml",
            top_category=top,
        )


# ===========================================================================
# LLM classifier (OpenAI GPT-4 structured output)
# ===========================================================================

_LLM_CACHE: Dict[str, ClassificationResult] = {}
_LLM_CACHE_MAX = 1000

_LLM_PROMPT = """You are an expert penetration tester. Classify the following attack scenario into one or more of these categories:

Categories: {categories}

Definitions:
- cve_exploitation: Using known CVEs or exploit code against services/software
- brute_force: Password cracking, dictionary attacks, hash cracking
- web_app_attack: SQLi, XSS, directory busting, web vuln scanning, web exploits
- privilege_escalation: Gaining higher privileges on a compromised system
- lateral_movement: Moving between systems in a network (AD, pivoting, PtH)
- password_spray: Testing passwords across many accounts
- network_pivot: Tunneling/proxying through compromised hosts
- file_exfiltration: Stealing data from compromised systems
- persistence: Installing backdoors or maintaining access
- social_engineering: Phishing or human manipulation attacks

Scenario: {text}

Respond in JSON format:
{{
  "categories": ["category1", "category2"],
  "scores": {{"category1": 0.95, "category2": 0.70}},
  "reasoning": "brief explanation"
}}

Only include categories with confidence >= 0.3. Use only the exact category names listed above."""


class LLMClassifier:
    """GPT-4 based classifier with structured JSON output and result caching."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None):
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def predict(
        self, text: str, threshold: float = 0.3
    ) -> ClassificationResult:
        cache_key = hashlib.md5(f"{self._model}:{text}".encode()).hexdigest()  # nosec B324
        if cache_key in _LLM_CACHE:
            logger.debug("LLM classifier cache hit")
            return _LLM_CACHE[cache_key]

        if not self._api_key:
            logger.warning("No OpenAI API key; falling back to keyword classifier")
            return KeywordClassifier().predict(text, 0.0)

        try:
            import openai

            client = openai.OpenAI(api_key=self._api_key)
            prompt = _LLM_PROMPT.format(
                categories=", ".join(CATEGORIES),
                text=text,
            )
            response = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=300,
            )
            raw_json = response.choices[0].message.content or "{}"
            data = json.loads(raw_json)

            scores: Dict[str, float] = {cat: 0.0 for cat in CATEGORIES}
            for cat, score in data.get("scores", {}).items():
                if cat in scores:
                    scores[cat] = float(score)

            matched = [c for c, s in scores.items() if s >= threshold]
            matched.sort(key=lambda c: scores[c], reverse=True)
            top = matched[0] if matched else "web_app_attack"

            result = ClassificationResult(
                categories=matched or [top],
                scores=scores,
                method="llm",
                top_category=top,
            )

            # Cache with max-size eviction
            if len(_LLM_CACHE) >= _LLM_CACHE_MAX:
                oldest_key = next(iter(_LLM_CACHE))
                del _LLM_CACHE[oldest_key]
            _LLM_CACHE[cache_key] = result
            return result

        except Exception as exc:
            logger.error("LLM classification failed: %s; falling back to keyword", exc)
            return KeywordClassifier().predict(text, 0.0)


# ===========================================================================
# Hybrid classifier (ML primary + LLM secondary)
# ===========================================================================


class HybridClassifier:
    """
    Merges ML and LLM confidence scores.

    If the top ML score exceeds ``ml_confidence_threshold`` (default 0.7),
    the ML result is returned directly without calling the LLM.
    Otherwise, both scores are averaged and the merged result returned.
    """

    def __init__(
        self,
        ml_classifier: Optional[MLClassifier] = None,
        llm_classifier: Optional[LLMClassifier] = None,
        ml_confidence_threshold: float = 0.7,
    ):
        self._ml = ml_classifier
        self._llm = llm_classifier or LLMClassifier()
        self._kw = KeywordClassifier()
        self._ml_threshold = ml_confidence_threshold

    def predict(
        self, text: str, threshold: float = 0.3
    ) -> ClassificationResult:
        # --- ML prediction ---
        if self._ml and self._ml._is_trained:
            try:
                ml_result = self._ml.predict(text, threshold)
            except Exception as exc:
                logger.warning("ML classifier error: %s", exc)
                ml_result = None
        else:
            ml_result = None

        # High-confidence ML result — skip LLM
        if ml_result and ml_result.scores.get(ml_result.top_category, 0) >= self._ml_threshold:
            ml_result.method = "hybrid_ml"
            return ml_result

        # --- LLM prediction ---
        try:
            llm_result = self._llm.predict(text, threshold)
        except Exception as exc:
            logger.warning("LLM classifier error: %s", exc)
            llm_result = None

        # Merge scores (average when both available)
        if ml_result and llm_result:
            merged_scores: Dict[str, float] = {}
            for cat in CATEGORIES:
                ml_s = ml_result.scores.get(cat, 0.0)
                llm_s = llm_result.scores.get(cat, 0.0)
                merged_scores[cat] = (ml_s + llm_s) / 2.0

            matched = [c for c, s in merged_scores.items() if s >= threshold]
            matched.sort(key=lambda c: merged_scores[c], reverse=True)
            top = matched[0] if matched else "web_app_attack"

            return ClassificationResult(
                categories=matched or [top],
                scores=merged_scores,
                method="hybrid",
                top_category=top,
            )

        # Fall back to whichever is available
        if llm_result:
            return llm_result
        if ml_result:
            return ml_result
        return self._kw.predict(text, threshold)


# ===========================================================================
# IntentClassifier — public API
# ===========================================================================


class IntentClassifier:
    """
    Public API for attack intent classification.

    Respects the ``CLASSIFIER_MODE`` environment variable:
      keyword  — KeywordClassifier (default, zero dependencies)
      ml       — MLClassifier (requires scikit-learn)
      llm      — LLMClassifier (requires openai + OPENAI_API_KEY)
      hybrid   — HybridClassifier (recommended)

    Usage::

        clf = IntentClassifier()
        result = clf.classify("exploit vsftpd 2.3.4 backdoor")
        print(result.top_category)   # "cve_exploitation"
        print(result.categories)     # ["cve_exploitation"]
        print(result.scores)         # {"cve_exploitation": 0.95, ...}
    """

    def __init__(self):
        mode = os.environ.get("CLASSIFIER_MODE", "keyword").lower()
        self._mode = mode
        self._clf = self._build_classifier(mode)

    def _build_classifier(self, mode: str) -> Any:
        if mode == "keyword":
            return KeywordClassifier()

        if mode == "ml":
            ml = MLClassifier()
            if _MODEL_PATH.exists():
                try:
                    ml = MLClassifier.load()
                    return ml
                except Exception as exc:
                    logger.warning("Could not load ML model: %s — retraining", exc)
            if _TRAINING_DATA_PATH.exists():
                try:
                    ml.train()
                    ml.save()
                    return ml
                except Exception as exc:
                    logger.error("ML training failed: %s — falling back to keyword", exc)
            return KeywordClassifier()

        if mode == "llm":
            return LLMClassifier()

        if mode in ("hybrid", "auto"):
            ml: Optional[MLClassifier] = None
            if _MODEL_PATH.exists():
                try:
                    ml = MLClassifier.load()
                except Exception as exc:
                    logger.warning("Could not load ML model for hybrid: %s", exc)
            elif _TRAINING_DATA_PATH.exists():
                try:
                    ml = MLClassifier()
                    ml.train()
                    ml.save()
                except Exception as exc:
                    logger.warning("ML training failed for hybrid: %s", exc)
            return HybridClassifier(ml_classifier=ml)

        logger.warning("Unknown CLASSIFIER_MODE '%s'; defaulting to keyword", mode)
        return KeywordClassifier()

    def classify(self, text: str, threshold: float = 0.3) -> ClassificationResult:
        """
        Classify an attack scenario description.

        Parameters
        ----------
        text:      free-text attack scenario description
        threshold: minimum confidence to include a category (default 0.3).
                   When using the keyword classifier this is automatically
                   lowered to 0.0 since keyword scores are relative ratios,
                   not calibrated probabilities.

        Returns
        -------
        ClassificationResult with categories, scores, and top_category
        """
        if not text or not text.strip():
            return ClassificationResult(
                categories=["web_app_attack"],
                scores={c: 0.0 for c in CATEGORIES},
                method=self._mode,
                top_category="web_app_attack",
            )

        # For keyword mode: use threshold=0 so that any matching keyword wins.
        # Probability-based classifiers (ml/llm/hybrid) keep the caller threshold.
        effective_threshold = 0.0 if self._mode == "keyword" else threshold

        try:
            return self._clf.predict(text.strip(), effective_threshold)
        except Exception as exc:
            logger.error("Classification error: %s", exc, exc_info=True)
            return KeywordClassifier().predict(text, 0.0)

    def top_category(self, text: str) -> str:
        """Convenience method — returns only the top category name."""
        return self.classify(text).top_category

    def top_n_categories(self, text: str, n: int = 3) -> List[str]:
        """Return the top-N most confident categories."""
        result = self.classify(text)
        return result.categories[:n]
