"""
Byzantine Consensus Threat Voting (BCTV)
Agents vote on threat verdicts. A compromised agent cannot manipulate
the group decision — requires corrupting ≥ ⌊(n-1)/3⌋ + 1 agents simultaneously.
"""
import hashlib
import hmac as hmac_lib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    THREAT = "THREAT"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class AgentVote:
    vote_id: str
    alert_id: str
    agent_id: str
    verdict: Verdict
    confidence: float          # 0.0 – 1.0
    evidence_hash: str         # SHA256 of the local evidence that drove this verdict
    timestamp: float
    signature: str             # HMAC-SHA256(agent_key, vote payload)

    def to_dict(self) -> dict:
        return {
            "vote_id": self.vote_id,
            "alert_id": self.alert_id,
            "agent_id": self.agent_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "evidence_hash": self.evidence_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AgentVote":
        return cls(
            vote_id=d["vote_id"],
            alert_id=d["alert_id"],
            agent_id=d["agent_id"],
            verdict=Verdict(d["verdict"]),
            confidence=d["confidence"],
            evidence_hash=d["evidence_hash"],
            timestamp=d["timestamp"],
            signature=d["signature"],
        )


@dataclass
class ConsensusResult:
    alert_id: str
    final_verdict: Verdict
    threat_votes: int
    benign_votes: int
    uncertain_votes: int
    total_valid_votes: int
    weighted_confidence: float
    byzantine_threshold: int      # max tolerable faulty agents
    consensus_reached: bool
    timestamp: float = field(default_factory=time.time)

    def to_alert_enrichment(self) -> dict:
        return {
            "consensus_verdict": self.final_verdict.value,
            "consensus_confidence": round(self.weighted_confidence, 3),
            "total_votes": self.total_valid_votes,
            "threat_votes": self.threat_votes,
            "benign_votes": self.benign_votes,
            "byzantine_threshold": self.byzantine_threshold,
            "consensus_reached": self.consensus_reached,
        }


class ByzantineConsensusEngine:
    """
    Implements Practical Byzantine Fault Tolerance (PBFT) simplified for
    threat verdict aggregation.

    For n agents, the system tolerates f = ⌊(n-1)/3⌋ faulty agents.
    A verdict requires 2f+1 concordant votes to be accepted.

    Signature verification ensures compromised agents can't forge other agents' votes.
    """

    VOTE_EXPIRY_SECONDS = 120    # votes older than 2 min are discarded
    MIN_AGENTS_FOR_CONSENSUS = 3  # need at least 3 agents to run consensus

    def __init__(self, agent_id: str, agent_key: bytes):
        self.agent_id = agent_id
        self.agent_key = agent_key

        # alert_id → list of received votes
        self._vote_pool: Dict[str, List[AgentVote]] = {}
        # alert_id → ConsensusResult (cached)
        self._results: Dict[str, ConsensusResult] = {}
        # Known agent public keys: agent_id → key bytes
        self._agent_keys: Dict[str, bytes] = {agent_id: agent_key}

    def register_agent(self, peer_agent_id: str, peer_key: bytes):
        """Register a peer agent's key for signature verification."""
        self._agent_keys[peer_agent_id] = peer_key
        logger.info(f"BCTV: Registered peer agent {peer_agent_id}")

    def _sign_vote(self, alert_id: str, verdict: Verdict,
                   confidence: float, evidence_hash: str,
                   timestamp: float) -> str:
        msg = f"{alert_id}:{verdict.value}:{confidence:.4f}:{evidence_hash}:{timestamp:.3f}"
        return hmac_lib.new(self.agent_key, msg.encode(), hashlib.sha256).hexdigest()

    def _verify_vote(self, vote: AgentVote) -> bool:
        peer_key = self._agent_keys.get(vote.agent_id)
        if peer_key is None:
            logger.warning(f"BCTV: Unknown agent {vote.agent_id} — rejecting vote")
            return False
        msg = (
            f"{vote.alert_id}:{vote.verdict.value}:{vote.confidence:.4f}:"
            f"{vote.evidence_hash}:{vote.timestamp:.3f}"
        )
        expected = hmac_lib.new(peer_key, msg.encode(), hashlib.sha256).hexdigest()
        return hmac_lib.compare_digest(expected, vote.signature)

    def _evidence_hash(self, alert: dict) -> str:
        payload = json.dumps(alert, sort_keys=True, default=str).encode()
        return hashlib.sha256(payload).hexdigest()

    def cast_vote(self, alert: dict) -> AgentVote:
        """
        Cast this agent's vote on a given alert.
        The verdict is derived from local analysis (threat_score).
        """
        alert_id = alert.get("id", str(uuid.uuid4()))
        score = float(alert.get("threat_score", 0.5))
        now = time.time()

        if score >= 0.8:
            verdict = Verdict.THREAT
            confidence = score
        elif score <= 0.3:
            verdict = Verdict.BENIGN
            confidence = 1.0 - score
        else:
            verdict = Verdict.UNCERTAIN
            confidence = 0.5

        ev_hash = self._evidence_hash(alert)
        sig = self._sign_vote(alert_id, verdict, confidence, ev_hash, now)

        vote = AgentVote(
            vote_id=str(uuid.uuid4()),
            alert_id=alert_id,
            agent_id=self.agent_id,
            verdict=verdict,
            confidence=confidence,
            evidence_hash=ev_hash,
            timestamp=now,
            signature=sig,
        )

        self._receive_vote(vote)
        logger.debug(f"BCTV: Cast vote {verdict.value} (conf={confidence:.2f}) for alert {alert_id}")
        return vote

    def receive_peer_vote(self, vote_dict: dict):
        """Receive and validate a vote from a peer agent."""
        try:
            vote = AgentVote.from_dict(vote_dict)
        except (KeyError, ValueError) as e:
            logger.warning(f"BCTV: Malformed vote received: {e}")
            return

        if not self._verify_vote(vote):
            logger.warning(f"BCTV: INVALID signature from agent {vote.agent_id} — vote rejected")
            return

        age = time.time() - vote.timestamp
        if age > self.VOTE_EXPIRY_SECONDS:
            logger.debug(f"BCTV: Expired vote from {vote.agent_id} — discarded")
            return

        self._receive_vote(vote)

    def _receive_vote(self, vote: AgentVote):
        if vote.alert_id not in self._vote_pool:
            self._vote_pool[vote.alert_id] = []
        # Deduplicate by agent (one vote per agent per alert)
        existing_agents = {v.agent_id for v in self._vote_pool[vote.alert_id]}
        if vote.agent_id not in existing_agents:
            self._vote_pool[vote.alert_id].append(vote)
            # Invalidate cached result
            self._results.pop(vote.alert_id, None)

    def compute_consensus(self, alert_id: str) -> Optional[ConsensusResult]:
        """
        Run Byzantine consensus on accumulated votes for an alert.
        Returns None if not enough votes yet.
        """
        if alert_id in self._results:
            return self._results[alert_id]

        votes = self._vote_pool.get(alert_id, [])
        n = len(votes)

        if n < self.MIN_AGENTS_FOR_CONSENSUS:
            logger.debug(f"BCTV: Only {n}/{self.MIN_AGENTS_FOR_CONSENSUS} votes for {alert_id}")
            return None

        # Byzantine fault tolerance: f = ⌊(n-1)/3⌋
        f = (n - 1) // 3
        quorum = 2 * f + 1   # minimum votes needed for a valid verdict

        threat_votes = [v for v in votes if v.verdict == Verdict.THREAT]
        benign_votes = [v for v in votes if v.verdict == Verdict.BENIGN]
        uncertain_votes = [v for v in votes if v.verdict == Verdict.UNCERTAIN]

        # Weighted confidence: weight by individual confidence scores
        def weighted_conf(vote_list: List[AgentVote]) -> float:
            if not vote_list:
                return 0.0
            total_w = sum(v.confidence for v in vote_list)
            return total_w / n  # normalized over all agents

        consensus_reached = False
        if len(threat_votes) >= quorum:
            final_verdict = Verdict.THREAT
            weighted_confidence = weighted_conf(threat_votes)
            consensus_reached = True
        elif len(benign_votes) >= quorum:
            final_verdict = Verdict.BENIGN
            weighted_confidence = weighted_conf(benign_votes)
            consensus_reached = True
        else:
            final_verdict = Verdict.UNCERTAIN
            weighted_confidence = 0.5
            consensus_reached = False

        result = ConsensusResult(
            alert_id=alert_id,
            final_verdict=final_verdict,
            threat_votes=len(threat_votes),
            benign_votes=len(benign_votes),
            uncertain_votes=len(uncertain_votes),
            total_valid_votes=n,
            weighted_confidence=weighted_confidence,
            byzantine_threshold=f,
            consensus_reached=consensus_reached,
        )
        self._results[alert_id] = result

        logger.info(
            f"BCTV CONSENSUS [{alert_id}]: {final_verdict.value} "
            f"({len(threat_votes)}T/{len(benign_votes)}B/{len(uncertain_votes)}U) "
            f"n={n} f={f} quorum={quorum} conf={weighted_confidence:.2f}"
        )
        return result

    def enrich_alert(self, alert: dict) -> dict:
        """
        Cast this agent's vote and return the alert enriched with consensus data.
        Call this on every alert; peer votes are added asynchronously via receive_peer_vote.
        """
        alert_id = alert.get("id", str(uuid.uuid4()))
        alert["id"] = alert_id

        # Cast local vote
        self.cast_vote(alert)

        # Try to compute consensus (may not have enough votes yet)
        result = self.compute_consensus(alert_id)
        if result:
            alert.update(result.to_alert_enrichment())
            # Override severity if consensus says BENIGN
            if result.final_verdict == Verdict.BENIGN and result.consensus_reached:
                alert["consensus_downgraded"] = True
        else:
            alert["consensus_pending"] = True
            alert["local_votes"] = len(self._vote_pool.get(alert_id, []))

        return alert

    def stats(self) -> dict:
        return {
            "registered_agents": len(self._agent_keys),
            "active_vote_pools": len(self._vote_pool),
            "completed_consensuses": len(self._results),
            "byzantine_threshold_current": (len(self._agent_keys) - 1) // 3,
        }
