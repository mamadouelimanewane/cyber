"""
Gestionnaire de clés chaotiques — Time Shifting Algorithm.
Chaque seconde produit une clé différente dérivée du secret partagé + timestamp.
"""

import hashlib
import hmac
import struct
from functools import lru_cache


class ChaosKeyManager:
    """
    Dérive une clé AES-256 unique pour chaque seconde Unix.

    Deux agents partageant le même `shared_secret` et synchronisés
    sur NTP produiront la même clé pour la même seconde — permettant
    la vérification mutuelle sans échange de clé en temps réel.
    """

    KEY_LENGTH = 32  # 256 bits

    def __init__(self, shared_secret: str):
        # PBKDF2 sur le secret partagé — coûteux à bruteforcer
        self._master_key = hashlib.pbkdf2_hmac(
            "sha256",
            shared_secret.encode("utf-8"),
            b"gravity-security-v1",
            iterations=100_000,
            dklen=self.KEY_LENGTH,
        )

    @lru_cache(maxsize=10)
    def derive_key(self, timestamp_second: int) -> bytes:
        """
        Dérive la clé pour une seconde donnée.
        Cache LRU de 10 entrées pour gérer la dérive d'horloge (±2s).
        """
        ts_bytes = struct.pack(">Q", timestamp_second)
        key = hmac.new(self._master_key, ts_bytes, hashlib.sha256).digest()
        return key

    def rotate(self) -> bytes:
        """Force la rotation et retourne la nouvelle clé courante."""
        import time
        self.derive_key.cache_clear()
        return self.derive_key(int(time.time()))
