from dataclasses import dataclass, field
from typing import Dict, List
from datetime import datetime


@dataclass
class Host:
    ip: str
    hostname: str = "Unknown"
    fqdn: str = "Unknown"
    domain: str = "Unknown"
    os_info: str = "Unknown"
    smb_signing: bool = True
    smbv1: bool = False
    open_ports: Dict[int, str] = field(default_factory=dict)
    udp_ports: Dict[int, str] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        if self.fqdn != "Unknown":
            return self.fqdn
        if self.hostname != "Unknown":
            return self.hostname
        return self.ip

    @property
    def relay_candidate(self) -> bool:
        return not self.smb_signing


@dataclass
class CredentialResult:
    username: str
    password: str
    ip: str
    protocol: str
    success: bool
    is_admin: bool = False
    is_ntlm: bool = False
    local_auth: bool = False


@dataclass
class CommandRecord:
    command: str
    output: str
    return_code: int
    duration: float
    label: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class EnumSession:
    started_at: datetime = field(default_factory=datetime.now)
    hosts: Dict[str, "Host"] = field(default_factory=dict)
    credentials: List[CredentialResult] = field(default_factory=list)
    command_history: List[CommandRecord] = field(default_factory=list)
    domain: str = "Unknown"
    input_ips: List[str] = field(default_factory=list)
    use_proxy: bool = False
    use_ligolo: bool = False
    top_ports: int = 0
    web_exts: str = ""
    web_filter_words: int = 0
    web_filter_lines: int = 0
    web_filter_size: int = 0
    web_recurse: bool = False

    def get_or_create_host(self, ip: str) -> "Host":
        if ip not in self.hosts:
            self.hosts[ip] = Host(ip=ip)
        return self.hosts[ip]
