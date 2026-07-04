from insider_threat_detection.config import DetectionConfig
from insider_threat_detection.models import DetectionResult, NetworkEvent, UserProfile


class BehaviorProfiler:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def score_event(self, event: NetworkEvent, profile: UserProfile) -> DetectionResult:
        reasons: list[str] = []
        score = 0.0
        action = event.action.lower()

        if "test_site_access" in action and not (8 <= event.timestamp.hour < 17):
            score += 2.5
            reasons.append("test site access outside business hours")

        if profile.event_count >= self.config.warmup_events:
            hour_gap = abs(event.timestamp.hour - profile.average_hour)
            if hour_gap >= 6:
                score += self.config.unusual_hour_weight
                reasons.append("unusual access hour")

            if event.source_ip not in profile.source_ips:
                score += self.config.new_source_ip_weight
                reasons.append("new source IP")

            if event.destination_ip not in profile.destination_ips:
                score += self.config.new_destination_weight
                reasons.append("new destination IP")

            average_sent = max(profile.average_bytes_sent, 1.0)
            if event.bytes_sent > average_sent * 3:
                score += self.config.bytes_spike_weight
                reasons.append("bytes sent spike")

            if len(profile.recent_event_hours) >= 4:
                recent_same_hour = sum(
                    1 for hour in profile.recent_event_hours[-4:] if hour == event.timestamp.hour
                )
                if recent_same_hour >= 3:
                    score += self.config.frequency_spike_weight
                    reasons.append("burst activity in short period")

        return DetectionResult(
            score=round(score, 2),
            alert=score >= self.config.alert_threshold,
            reasons=reasons,
        )

    def update_profile(self, event: NetworkEvent, profile: UserProfile) -> None:
        profile.event_count += 1
        profile.total_bytes_sent += event.bytes_sent
        profile.total_bytes_received += event.bytes_received
        profile.hour_sum += event.timestamp.hour
        profile.source_ips.add(event.source_ip)
        profile.destination_ips.add(event.destination_ip)
        profile.recent_event_hours.append(event.timestamp.hour)
        if len(profile.recent_event_hours) > 20:
            profile.recent_event_hours.pop(0)
