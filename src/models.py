from dataclasses import dataclass


@dataclass
class DynamicRule:
    rule_id: str
    src_ip: str
    dst_ip: str = ""
    proto: str = "tcp"
    dst_port: int | None = None
    ttl: int = 60
    reason: str = ""
    action: str = "drop"

    @property
    def protocol(self) -> str:
        # Alias para NftablesExecutor
        return self.proto

    @property
    def ip_version(self) -> int:
        return 6 if ":" in str(self.src_ip) else 4