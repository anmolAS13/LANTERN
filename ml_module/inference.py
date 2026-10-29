
from pathlib import Path
from numbers import Integral

import joblib
import pandas as pd


MODEL_DIR = Path(__file__).resolve().parent / "models"


class MLInference:
    def __init__(self, model_dir=MODEL_DIR):
        model_dir = Path(model_dir)

        self.classifier = joblib.load(
            model_dir / "attack_classifier.pkl"
        )
        self.feature_columns = joblib.load(
            model_dir / "feature_columns.pkl"
        )
        self.attack_classes = joblib.load(
            model_dir / "attack_classes.pkl"
        )
        self.anomaly_detector = joblib.load(
            model_dir / "anomaly_detector.pkl"
        )

        if hasattr(self.feature_columns, "tolist"):
            self.feature_columns = self.feature_columns.tolist()

        self.feature_columns = list(self.feature_columns)

        if not self.feature_columns:
            raise ValueError("The saved feature list is empty.")

    def _prepare_input(self, features: dict) -> pd.DataFrame:

        missing = [
            col for col in self.feature_columns
            if col not in features
        ]

        if missing:
            raise ValueError(
                f"Missing model features: {missing}"
            )

        row = {
            col: features[col]
            for col in self.feature_columns
        }

        frame = pd.DataFrame(
            [row],
            columns=self.feature_columns,
        )

        if frame.isnull().any().any():
            raise ValueError("Feature input contains missing values.")

        return frame

    def predict(self, features: dict) -> dict:
        """Run attack classification and anomaly detection."""
        X = self._prepare_input(features)

        # 1. Classify the type of traffic/attack.
        predicted_class = self.classifier.predict(X)[0]

        # Resolve class names where the saved mapping supports it.
        if isinstance(self.attack_classes, dict):
            attack_name = self.attack_classes.get(
                predicted_class,
                self.attack_classes.get(
                    str(predicted_class),
                    str(predicted_class),
                ),
            )
        elif hasattr(self.attack_classes, "inverse_transform"):
            attack_name = self.attack_classes.inverse_transform([predicted_class])[0]
        elif isinstance(self.attack_classes, (list, tuple)) or hasattr(self.attack_classes, "tolist"):
            if (
                isinstance(predicted_class, Integral)
                and 0 <= predicted_class < len(self.attack_classes)
            ):
                attack_name = self.attack_classes[predicted_class]
            else:
                attack_name = str(predicted_class)
        else:
            attack_name = str(predicted_class)

        # 2. Detect anomalous traffic.
        anomaly_prediction = self.anomaly_detector.predict(X)[0]

        # Standard convention used by IsolationForest,
        # LocalOutlierFactor and OneClassSVM:
        # -1 = anomaly; +1 = inlier.
        # Verify this against your actual trained detector.
        is_anomaly = bool(anomaly_prediction == -1)

        result = {
            "attack_class": str(attack_name),
            "is_anomaly": is_anomaly,
            "anomaly_prediction": anomaly_prediction.item()
            if hasattr(anomaly_prediction, "item")
            else anomaly_prediction,
        }

        # Classification confidence, only if the model supports it.
        if hasattr(self.classifier, "predict_proba"):
            probabilities = self.classifier.predict_proba(X)[0]
            result["classification_confidence"] = float(
                max(probabilities)
            )

        # Optional anomaly score. Its meaning and direction depend
        # on the model, so retain the raw value.
        if hasattr(self.anomaly_detector, "decision_function"):
            score = self.anomaly_detector.decision_function(X)[0]
            result["anomaly_score"] = float(score)

        return result
