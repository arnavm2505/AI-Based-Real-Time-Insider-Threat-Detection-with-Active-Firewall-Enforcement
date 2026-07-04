from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    alert_threshold: float = 2.5
    unusual_hour_weight: float = 0.9
    new_source_ip_weight: float = 0.8
    new_destination_weight: float = 0.7
    bytes_spike_weight: float = 1.0
    frequency_spike_weight: float = 0.8
    warmup_events: int = 5
