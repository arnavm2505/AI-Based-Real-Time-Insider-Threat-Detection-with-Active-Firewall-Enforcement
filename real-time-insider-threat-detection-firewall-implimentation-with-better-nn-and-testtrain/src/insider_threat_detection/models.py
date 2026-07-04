from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NetworkEvent:
    timestamp: datetime
    user_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    action: str
    bytes_sent: int
    bytes_received: int


@dataclass
class UserProfile:
    user_id: str
    event_count: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    hour_sum: int = 0
    source_ips: set[str] = field(default_factory=set)
    destination_ips: set[str] = field(default_factory=set)
    recent_event_hours: list[int] = field(default_factory=list)

    @property
    def average_bytes_sent(self) -> float:
        return self.total_bytes_sent / self.event_count if self.event_count else 0.0

    @property
    def average_bytes_received(self) -> float:
        return self.total_bytes_received / self.event_count if self.event_count else 0.0

    @property
    def average_hour(self) -> float:
        return self.hour_sum / self.event_count if self.event_count else 0.0


@dataclass
class DetectionResult:
    score: float
    alert: bool
    reasons: list[str]
