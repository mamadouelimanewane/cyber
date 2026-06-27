"""
Gravity Security — Mathematical Chaos Engine
Inspiré du Time Shifting Algorithm de Cyber 2.0.

Principe : utilise les équations chaotiques de Lorenz et la logistic map
pour générer des clés de chiffrement qui changent chaque seconde.
Seuls les agents autorisés connaissent les paramètres initiaux →
tout trafic non chiffré avec la bonne clé est rejeté automatiquement.
"""

import time
import hashlib
import hmac
import struct
import math
from typing import Tuple
from .key_manager import ChaosKeyManager


class ChaosEngine:
    """
    Moteur de chiffrement basé sur la théorie du chaos.

    La logistic map x_{n+1} = r * x_n * (1 - x_n) avec r proche de 4
    produit une séquence pseudo-aléatoire extrêmement sensible aux
    conditions initiales — deux agents avec des x0 différents de 1e-15
    divergent complètement après quelques itérations.
    """

    LORENZ_SIGMA = 10.0
    LORENZ_RHO = 28.0
    LORENZ_BETA = 8.0 / 3.0
    LOGISTIC_R = 3.9999

    def __init__(self, agent_id: str, shared_secret: str):
        self.agent_id = agent_id
        self.key_manager = ChaosKeyManager(shared_secret)
        self._current_key: bytes = b""
        self._key_timestamp: int = 0

    # ------------------------------------------------------------------ #
    #  Clé courante (change chaque seconde — Time Shifting Algorithm)     #
    # ------------------------------------------------------------------ #

    def get_current_key(self) -> bytes:
        """Retourne la clé active pour la seconde courante."""
        now = int(time.time())
        if now != self._key_timestamp:
            self._current_key = self.key_manager.derive_key(now)
            self._key_timestamp = now
        return self._current_key

    # ------------------------------------------------------------------ #
    #  Lorenz Attractor — génère un vecteur d'initialisation chaotique   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def lorenz_step(x: float, y: float, z: float, dt: float = 0.01) -> Tuple[float, float, float]:
        dx = ChaosEngine.LORENZ_SIGMA * (y - x)
        dy = x * (ChaosEngine.LORENZ_RHO - z) - y
        dz = x * y - ChaosEngine.LORENZ_BETA * z
        return x + dx * dt, y + dy * dt, z + dz * dt

    @staticmethod
    def lorenz_sequence(x0: float, y0: float, z0: float, steps: int = 100) -> bytes:
        """Génère N octets chaotiques depuis les conditions initiales (x0, y0, z0)."""
        x, y, z = x0, y0, z0
        result = bytearray()
        for _ in range(steps):
            x, y, z = ChaosEngine.lorenz_step(x, y, z)
            # Extraire l'octet de poids faible de chaque coordonnée
            result.append(int(abs(x) * 1000) % 256)
            result.append(int(abs(y) * 1000) % 256)
            result.append(int(abs(z) * 1000) % 256)
        return bytes(result[:steps])

    # ------------------------------------------------------------------ #
    #  Logistic Map — second générateur chaotique                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def logistic_sequence(x0: float, steps: int = 32) -> bytes:
        """Génère une séquence chaotique via la logistic map."""
        x = x0
        result = bytearray()
        for _ in range(steps):
            x = ChaosEngine.LOGISTIC_R * x * (1.0 - x)
            result.append(int(x * 256) % 256)
        return bytes(result)

    # ------------------------------------------------------------------ #
    #  Chiffrement / Déchiffrement XOR-Chaos                             #
    # ------------------------------------------------------------------ #

    def encrypt(self, data: bytes) -> bytes:
        """
        Chiffre les données avec la clé chaotique courante.
        Ajoute un timestamp + HMAC pour l'authenticité.
        """
        key = self.get_current_key()
        timestamp = int(time.time())

        # Chiffrement XOR avec keystream dérivé de la clé chaotique
        keystream = self._generate_keystream(key, len(data))
        ciphertext = bytes(a ^ b for a, b in zip(data, keystream))

        # Paquet : [timestamp:4][agent_id_hash:8][ciphertext][hmac:32]
        ts_bytes = struct.pack(">I", timestamp)
        agent_hash = hashlib.sha256(self.agent_id.encode()).digest()[:8]
        payload = ts_bytes + agent_hash + ciphertext
        mac = hmac.new(key, payload, hashlib.sha256).digest()

        return payload + mac

    def decrypt(self, packet: bytes) -> Tuple[bytes, bool]:
        """
        Déchiffre et vérifie l'authenticité du paquet.
        Retourne (données, valide).
        """
        if len(packet) < 44:  # 4 + 8 + 32 minimum
            return b"", False

        mac_received = packet[-32:]
        payload = packet[:-32]
        ts_bytes = payload[:4]
        ciphertext = payload[12:]

        timestamp = struct.unpack(">I", ts_bytes)[0]
        now = int(time.time())

        # Tolérance de ±2 secondes pour la dérive d'horloge
        if abs(now - timestamp) > 2:
            return b"", False

        # Utiliser la clé du timestamp du paquet (pas forcément now)
        key = self.key_manager.derive_key(timestamp)

        # Vérification HMAC
        mac_expected = hmac.new(key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_received, mac_expected):
            return b"", False

        # Déchiffrement
        keystream = self._generate_keystream(key, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        return plaintext, True

    def _generate_keystream(self, key: bytes, length: int) -> bytes:
        """Génère un keystream via lorenz + logistic map combinés."""
        # Conditions initiales dérivées de la clé
        x0 = (int.from_bytes(key[:4], "big") / 2**32) * 0.8 + 0.1
        y0 = (int.from_bytes(key[4:8], "big") / 2**32) * 0.8 + 0.1
        z0 = (int.from_bytes(key[8:12], "big") / 2**32) * 20.0 + 5.0
        lx0 = (int.from_bytes(key[12:16], "big") / 2**32) * 0.6 + 0.2

        lorenz_bytes = self.lorenz_sequence(x0, y0, z0, steps=length)
        logistic_bytes = self.logistic_sequence(lx0, steps=length)

        # XOR des deux séquences chaotiques → keystream final
        return bytes(a ^ b for a, b in zip(lorenz_bytes, logistic_bytes))

    # ------------------------------------------------------------------ #
    #  Signature de paquet (pour le NAC)                                 #
    # ------------------------------------------------------------------ #

    def sign_packet(self, packet: bytes) -> bytes:
        """Ajoute une signature chaotique à un paquet réseau."""
        key = self.get_current_key()
        sig = hmac.new(key, packet, hashlib.sha256).digest()[:8]
        return packet + sig

    def verify_packet(self, signed_packet: bytes) -> bool:
        """Vérifie la signature d'un paquet réseau. Rejette si invalide."""
        if len(signed_packet) < 9:
            return False
        packet = signed_packet[:-8]
        sig_received = signed_packet[-8:]
        key = self.get_current_key()
        sig_expected = hmac.new(key, packet, hashlib.sha256).digest()[:8]
        return hmac.compare_digest(sig_received, sig_expected)
