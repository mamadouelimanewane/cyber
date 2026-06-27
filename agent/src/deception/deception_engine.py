"""
Gravity Security — Deception Engine (Honeypots & Honeytokens)
Innovation : transformer chaque machine protégée en piège actif.

Principe "Active Defense" :
Au lieu d'attendre passivement que l'attaquant frappe, on lui tend des pièges.
Si quelqu'un touche un honeytoken, c'est forcément un attaquant (aucun utilisateur
légitime n'a de raison d'accéder à ces ressources).

Types de pièges déployés :
1. Honeytokens fichiers : fichiers leurres (passwords.txt, config.json, etc.)
2. Honeytokens registre : clés de registre factices avec fausses credentials
3. Honey credentials : comptes utilisateurs factices dans Active Directory
4. Honey services : ports ouverts factices qui alertent à la première connexion
5. Honey processes : processus leurres qui semblent être des cibles précieuses

Chaque interaction avec ces leurres révèle les TTPs de l'attaquant
et génère une alerte CRITIQUE immédiate avec collecte de forensics.
"""

import os
import json
import time
import socket
import hashlib
import logging
import threading
import tempfile
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("gravity.deception")

DECEPTION_DIR = Path(__file__).parent.parent.parent.parent / "data" / "deception"


@dataclass
class HoneyToken:
    token_id: str
    token_type: str        # "file", "registry", "credential", "port", "process"
    path: str              # Chemin ou identifiant du leurre
    description: str       # Description lisible
    deployed_at: float = field(default_factory=time.time)
    triggered: bool = False
    trigger_count: int = 0
    last_triggered: Optional[float] = None
    attacker_info: Dict = field(default_factory=dict)


@dataclass
class DeceptionEvent:
    """Événement généré quand un attaquant touche un leurre."""
    token_id: str
    token_type: str
    timestamp: float
    pid: Optional[int]
    process_name: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    details: Dict
    forensics: Dict       # Données collectées automatiquement sur l'attaquant


class DeceptionEngine:
    """
    Moteur de déception active — déploie et surveille les honeytokens.

    Dès qu'un attaquant interagit avec un leurre :
    1. Alerte CRITIQUE immédiate
    2. Collecte automatique de forensics (processus, réseau, utilisateur)
    3. Propagation aux autres agents (l'attaquant est maintenant connu)
    4. Option : contre-déception (donner de fausses informations à l'attaquant)
    """

    # Templates de fichiers leurres — semblent précieux pour un attaquant
    HONEY_FILE_TEMPLATES = [
        {
            "filename": "passwords_backup.txt",
            "content": "# Backup passwords - DO NOT SHARE\nadmin:Tr0ub4dor&3\nroot:P@ssw0rd123!\nbackup_svc:Summer2024!\ndb_admin:Qwerty!@#$\n",
            "description": "Fichier de mots de passe factice",
        },
        {
            "filename": "vpn_credentials.json",
            "content": json.dumps({
                "vpn_server": "vpn.company-internal.com",
                "username": "svc_vpn_backup",
                "password": "VPN_B4ckup_2024!",
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIFakeHoneyCert...\n-----END CERTIFICATE-----"
            }, indent=2),
            "description": "Credentials VPN factices",
        },
        {
            "filename": "database_config.env",
            "content": "DB_HOST=192.168.1.100\nDB_PORT=5432\nDB_NAME=production\nDB_USER=postgres\nDB_PASSWORD=S3cur3Pr0d!2024\nDB_SSL=true\n",
            "description": "Configuration base de données factice",
        },
        {
            "filename": "aws_credentials",
            "content": "[default]\naws_access_key_id = AKIAFAKE123HONEYTOKEN\naws_secret_access_key = fake+secret+key+gravity+security+honeytoken\nregion = us-east-1\n",
            "description": "Credentials AWS factices (honeytokens)",
        },
        {
            "filename": "ssh_private_key.pem",
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA[HONEYTOKEN_GRAVITY_SECURITY_FAKE_KEY]\n-----END RSA PRIVATE KEY-----\n",
            "description": "Clé SSH privée factice",
        },
    ]

    # Ports leurres à surveiller
    HONEY_PORTS = [
        (4444, "Meterpreter default port (leurre attaquant)"),
        (1337, "Port hacker classique (leurre)"),
        (31337, "Elite port (leurre)"),
        (8888, "Jupyter/alternative web (leurre)"),
    ]

    def __init__(self, deploy_dir: Optional[str] = None, callback: Optional[Callable] = None):
        self.deploy_dir = Path(deploy_dir) if deploy_dir else DECEPTION_DIR / "tokens"
        self.callback = callback
        self._tokens: Dict[str, HoneyToken] = {}
        self._events: List[DeceptionEvent] = []
        self._watchers: List[threading.Thread] = []
        self._running = False
        self._port_listeners: List[socket.socket] = []

    # ------------------------------------------------------------------ #
    #  Déploiement des leurres                                          #
    # ------------------------------------------------------------------ #

    def deploy_all(self):
        """Déploie tous les types de honeytokens."""
        self.deploy_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Déploiement des honeytokens dans {self.deploy_dir}")

        self._deploy_honey_files()
        self._deploy_honey_ports()
        self._running = True

        logger.info(f"Déception Engine actif — {len(self._tokens)} honeytokens déployés")

    def _deploy_honey_files(self):
        """Crée les fichiers leurres dans des emplacements stratégiques."""
        deploy_locations = [
            self.deploy_dir,
            Path.home() / "Documents",
            Path.home() / "Desktop",
        ]

        for location in deploy_locations:
            try:
                location.mkdir(parents=True, exist_ok=True)
                for template in self.HONEY_FILE_TEMPLATES:
                    file_path = location / template["filename"]
                    token_id = hashlib.sha256(str(file_path).encode()).hexdigest()[:16]

                    # Écrire le fichier leurre
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(template["content"])

                    # Cacher le contenu dans les métadonnées (le vrai "trigger" est l'accès)
                    token = HoneyToken(
                        token_id=token_id,
                        token_type="file",
                        path=str(file_path),
                        description=template["description"],
                    )
                    self._tokens[token_id] = token

                    # Démarrer la surveillance de ce fichier
                    self._watch_file(file_path, token_id)
                    logger.debug(f"Honeytoken déployé: {file_path}")

            except (PermissionError, OSError) as e:
                logger.debug(f"Impossible de déployer dans {location}: {e}")

    def _deploy_honey_ports(self):
        """Ouvre des ports leurres qui alertent à la première connexion."""
        for port, description in self.HONEY_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.listen(5)
                sock.settimeout(1.0)

                token_id = f"port_{port}"
                self._tokens[token_id] = HoneyToken(
                    token_id=token_id,
                    token_type="port",
                    path=f"0.0.0.0:{port}",
                    description=description,
                )
                self._port_listeners.append(sock)

                # Thread d'écoute
                t = threading.Thread(
                    target=self._listen_honey_port,
                    args=(sock, port, token_id),
                    daemon=True
                )
                t.start()
                self._watchers.append(t)
                logger.info(f"Honey port ouvert: {port}/tcp — {description}")

            except OSError as e:
                logger.debug(f"Port {port} non disponible: {e}")

    # ------------------------------------------------------------------ #
    #  Surveillance des fichiers                                        #
    # ------------------------------------------------------------------ #

    def _watch_file(self, file_path: Path, token_id: str):
        """Surveille l'accès à un fichier honeytoken via polling de stat."""
        def watcher():
            try:
                last_atime = file_path.stat().st_atime
                while self._running:
                    time.sleep(5)
                    if not file_path.exists():
                        continue
                    current_atime = file_path.stat().st_atime
                    if current_atime != last_atime:
                        self._trigger_file_token(token_id, str(file_path))
                        last_atime = current_atime
            except Exception:
                pass

        t = threading.Thread(target=watcher, daemon=True)
        t.start()
        self._watchers.append(t)

    def _trigger_file_token(self, token_id: str, file_path: str):
        """Déclenché quand un honeytoken fichier est accédé."""
        forensics = self._collect_forensics()
        event = DeceptionEvent(
            token_id=token_id,
            token_type="file",
            timestamp=time.time(),
            pid=forensics.get("suspicious_pid"),
            process_name=forensics.get("suspicious_process"),
            username=forensics.get("current_user"),
            source_ip=None,
            details={"file_path": file_path, "access_type": "read"},
            forensics=forensics,
        )
        self._record_event(event, token_id)

    # ------------------------------------------------------------------ #
    #  Surveillance des ports                                           #
    # ------------------------------------------------------------------ #

    def _listen_honey_port(self, sock: socket.socket, port: int, token_id: str):
        """Écoute un port leurre et alerte à la première connexion."""
        while self._running:
            try:
                conn, addr = sock.accept()
                source_ip = addr[0]
                forensics = self._collect_forensics()
                forensics["connection_from"] = f"{source_ip}:{addr[1]}"

                # Envoyer une réponse leurre pour garder l'attaquant occupé
                try:
                    conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                    time.sleep(2)
                    conn.close()
                except Exception:
                    pass

                event = DeceptionEvent(
                    token_id=token_id,
                    token_type="port",
                    timestamp=time.time(),
                    pid=None,
                    process_name=None,
                    username=None,
                    source_ip=source_ip,
                    details={"port": port, "source": f"{source_ip}:{addr[1]}"},
                    forensics=forensics,
                )
                self._record_event(event, token_id)

            except socket.timeout:
                pass
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    #  Collecte de forensics                                           #
    # ------------------------------------------------------------------ #

    def _collect_forensics(self) -> Dict:
        """Collecte automatiquement des données forensics au moment du trigger."""
        forensics = {"collected_at": datetime.utcnow().isoformat()}
        try:
            import psutil, os
            forensics["current_user"] = os.environ.get("USERNAME", "unknown")
            forensics["hostname"] = socket.gethostname()

            # Processus récemment lancés (dernières 30 secondes)
            recent_procs = []
            now = time.time()
            for p in psutil.process_iter(["pid", "name", "create_time", "username", "exe"]):
                try:
                    if now - p.info["create_time"] < 30:
                        recent_procs.append({
                            "pid": p.info["pid"],
                            "name": p.info["name"],
                            "age_seconds": round(now - p.info["create_time"], 1),
                        })
                except Exception:
                    pass
            forensics["recent_processes"] = recent_procs[:10]

            # Connexions réseau actives
            connections = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    connections.append(f"{conn.raddr.ip}:{conn.raddr.port}")
            forensics["active_connections"] = connections[:10]

        except Exception as e:
            forensics["error"] = str(e)
        return forensics

    # ------------------------------------------------------------------ #
    #  Enregistrement & Alertes                                        #
    # ------------------------------------------------------------------ #

    def _record_event(self, event: DeceptionEvent, token_id: str):
        """Enregistre l'événement et génère l'alerte CRITIQUE."""
        if token_id in self._tokens:
            token = self._tokens[token_id]
            token.triggered = True
            token.trigger_count += 1
            token.last_triggered = event.timestamp

        self._events.append(event)

        alert = {
            "type": "HONEYTOKEN_TRIGGERED",
            "severity": "critical",
            "threat_score": 1.0,
            "token_type": event.token_type,
            "reason": (
                f"HONEYTOKEN DÉCLENCHÉ — {event.token_type.upper()} "
                f"'{self._tokens.get(token_id, HoneyToken('', '', '', '')).description}' "
                f"accédé par {event.process_name or event.source_ip or 'inconnu'}"
            ),
            "label": "Attaquant détecté — Honeytoken",
            "action": "INCIDENT CONFIRMÉ — Activer le plan de réponse immédiatement",
            "forensics": event.forensics,
            "source_ip": event.source_ip,
            "process": event.process_name,
        }

        logger.critical(
            f"[HONEYTOKEN] ATTAQUANT DÉTECTÉ — {event.token_type} "
            f"'{token_id}' déclenché depuis {event.source_ip or event.process_name}"
        )

        if self.callback:
            self.callback(alert)

    def stop(self):
        self._running = False
        for sock in self._port_listeners:
            try:
                sock.close()
            except Exception:
                pass

    def get_status(self) -> Dict:
        return {
            "tokens_deployed": len(self._tokens),
            "tokens_triggered": sum(1 for t in self._tokens.values() if t.triggered),
            "total_events": len(self._events),
            "tokens": [
                {
                    "id": t.token_id, "type": t.token_type,
                    "description": t.description,
                    "triggered": t.triggered,
                    "trigger_count": t.trigger_count,
                }
                for t in self._tokens.values()
            ],
        }
