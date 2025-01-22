#!/usr/bin/env python3
"""
Train the ML intent classifier for the attack path router.

Reads training data from ``backend/data/intent_training_data.json``,
trains a multi-label SVM classifier, and saves the model artifact to
``backend/data/classifier_model.pkl``.

Usage::

    python scripts/train_classifier.py [--evaluate]

Options:
    --evaluate   Run 5-fold cross-validation and print accuracy metrics.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "backend" / "data"
BACKEND_DIR = REPO_ROOT / "backend"

# Add backend to sys.path so we can import app modules
sys.path.insert(0, str(BACKEND_DIR))


def train(evaluate: bool = False) -> None:
    """Train and save the ML classifier."""
    try:
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.metrics import classification_report
        from sklearn.model_selection import cross_val_score
        from sklearn.multiclass import OneVsRestClassifier
        from sklearn.preprocessing import MultiLabelBinarizer
        from sklearn.svm import LinearSVC
    except ImportError:
        logger.error("scikit-learn is required. Install: pip install scikit-learn")
        sys.exit(1)

    training_path = DATA_DIR / "intent_training_data.json"
    model_path = DATA_DIR / "classifier_model.pkl"

    if not training_path.exists():
        logger.error("Training data not found: %s", training_path)
        sys.exit(1)

    logger.info("Loading training data from %s", training_path)
    with open(training_path) as fh:
        raw = json.load(fh)

    texts = [item["text"] for item in raw]
    labels = [item["labels"] for item in raw]
    logger.info("Loaded %d training examples", len(texts))

    # Import classifier
    from app.agent.classification.feature_extractor import FeatureExtractor, TECHNIQUE_KEYWORDS
    from app.agent.classification.intent_classifier import CATEGORIES, MLClassifier

    # Train
    ml = MLClassifier()
    ml.train(data_path=training_path)

    # Optional evaluation
    if evaluate:
        logger.info("Running cross-validation evaluation...")
        binarizer = MultiLabelBinarizer(classes=CATEGORIES)
        y = binarizer.fit_transform(labels)

        fe = FeatureExtractor()
        X = fe.fit_transform(texts)

        base_clf = LinearSVC(max_iter=2000, C=1.0)
        calibrated = CalibratedClassifierCV(base_clf, cv=3)
        clf = OneVsRestClassifier(calibrated)

        # Micro-averaged F1 cross-validation
        scores = cross_val_score(clf, X, y, cv=5, scoring="f1_micro")
        logger.info("5-fold CV micro-F1: %.3f +/- %.3f", scores.mean(), scores.std())

        # Train on all data and print classification report
        clf.fit(X, y)
        y_pred = clf.predict(X)
        print("\nClassification Report (training set):")
        print(classification_report(y, y_pred, target_names=CATEGORIES))

    # Save model
    ml.save(model_path=model_path)
    logger.info("Model saved to %s", model_path)

    # Quick sanity test
    test_cases = [
        ("exploit vsftpd 2.3.4 backdoor", "cve_exploitation"),
        ("sqlmap SQL injection web form", "web_app_attack"),
        ("crack NTLM hash with hashcat wordlist", "brute_force"),
        ("linpeas privilege escalation enumeration", "privilege_escalation"),
    ]

    logger.info("Sanity checks:")
    for text, expected in test_cases:
        result = ml.predict(text)
        ok = result.top_category == expected
        status = "OK" if ok else "FAIL"
        logger.info("  [%s] '%s' -> %s", status, text, result.top_category)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the ML intent classifier")
    parser.add_argument(
        "--evaluate", action="store_true",
        help="Run cross-validation and print metrics"
    )
    args = parser.parse_args()
    train(evaluate=args.evaluate)
