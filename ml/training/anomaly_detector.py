"""
Gravity Security — Détecteur d'Anomalies ML (Non-Supervisé)
Utilise Isolation Forest pour détecter les comportements inhabituels
sans avoir besoin d'exemples labellisés de malwares.

Principe : apprend le comportement NORMAL du système → tout écart = suspect.
"""

import numpy as np
import joblib
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Tuple

logger = logging.getLogger("gravity.ml.anomaly")

MODEL_PATH = Path(__file__).parent.parent / "models" / "anomaly_detector.pkl"
SCALER_PATH = Path(__file__).parent.parent / "models" / "scaler.pkl"


def extract_features(process_data: Dict) -> List[float]:
    """
    Transforme les données d'un processus en vecteur numérique.
    Features : comportement réseau, CPU, mémoire, nb enfants, profondeur chaîne...
    """
    return [
        float(process_data.get("threat_score", 0.0)),
        float(process_data.get("cpu_percent", 0.0)),
        float(process_data.get("memory_mb", 0.0)),
        float(len(process_data.get("connections", []))),
        float(len(process_data.get("children", []))),
        float(process_data.get("chain_depth", 0)),
        float(process_data.get("entropy", 0.0)),
        1.0 if process_data.get("name", "") in _lolbins() else 0.0,
        1.0 if process_data.get("has_network", False) else 0.0,
        1.0 if process_data.get("parent_is_office", False) else 0.0,
    ]


def _lolbins():
    return {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    }


class AnomalyDetector:
    """
    Détecteur d'anomalies basé sur Isolation Forest.

    Phase 1 — Apprentissage (mode normal) :
        Le modèle observe le système pendant X minutes/heures
        et apprend à reconnaître le comportement normal.

    Phase 2 — Détection :
        Tout processus dont le score d'anomalie dépasse le seuil
        est signalé comme suspect — même s'il n'est pas dans une base de signatures.
    """

    def __init__(self, contamination: float = 0.05):
        """
        contamination : fraction estimée d'anomalies dans les données d'entraînement.
        0.05 = on s'attend à ce que 5% des processus soient anormaux.
        """
        self.contamination = contamination
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self._is_trained = False

    def fit(self, normal_samples: List[Dict]):
        """Entraîne le modèle sur des données de comportement normal."""
        if len(normal_samples) < 50:
            logger.warning("Moins de 50 échantillons — modèle peu fiable")

        X = np.array([extract_features(s) for s in normal_samples])
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self._is_trained = True
        logger.info(f"Modèle entraîné sur {len(normal_samples)} échantillons")

    def predict(self, process_data: Dict) -> Tuple[bool, float]:
        """
        Prédit si un processus est anormal.
        Retourne (is_anomaly, anomaly_score) où score ∈ [0, 1].
        """
        if not self._is_trained:
            return False, 0.0

        features = np.array([extract_features(process_data)])
        features_scaled = self.scaler.transform(features)

        # Isolation Forest retourne -1 (anomalie) ou 1 (normal)
        prediction = self.model.predict(features_scaled)[0]
        # Score de décision : plus négatif = plus anormal
        decision = self.model.decision_function(features_scaled)[0]
        # Normaliser en [0, 1] — 1.0 = très anormal
        anomaly_score = max(0.0, min(1.0, (-decision + 0.5) / 1.0))

        is_anomaly = prediction == -1
        return is_anomaly, round(anomaly_score, 3)

    def save(self):
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        logger.info(f"Modèle sauvegardé: {MODEL_PATH}")

    def load(self) -> bool:
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self._is_trained = True
            logger.info("Modèle chargé depuis le disque")
            return True
        return False

    @property
    def is_trained(self) -> bool:
        return self._is_trained


# ------------------------------------------------------------------ #
#  Script d'entraînement standalone                                  #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python anomaly_detector.py <fichier_donnees.json>")
        print("\nFormat attendu : liste de dicts avec les champs de processus")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(data)
    detector.save()
    print(f"✓ Modèle entraîné sur {len(data)} échantillons et sauvegardé")
