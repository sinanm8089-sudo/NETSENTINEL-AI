"""Hybrid Command Terminal Parser & Dispatcher Validator for Cybersecurity Engineers."""
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ValidatedCommand:
    raw: str
    is_allowed: bool
    command_type: str
    args: Dict[str, str]
    rejection_reason: Optional[str] = None


def validate_terminal_command(raw_command: str) -> ValidatedCommand:
    """
    Parses platform commands (help, assets, ports, changes, status, findings, scan, investigate, optimize, clear)
    and routes any 'shell <cmd>' or direct OS/network CLI commands to full shell execution for cybersecurity engineers.
    """
    if not raw_command or not raw_command.strip():
        return ValidatedCommand(
            raw="",
            is_allowed=False,
            command_type="EMPTY",
            args={},
            rejection_reason="Empty command.",
        )

    cmd = raw_command.strip()
    normalized = " ".join(cmd.split())

    # Exact built-in platform commands
    simple_commands = {
        "help": "HELP",
        "assets": "ASSETS",
        "ports": "PORTS_ALL",
        "changes": "CHANGES",
        "status": "STATUS",
        "findings": "FINDINGS",
        "optimize": "OPTIMIZE",
        "clear": "CLEAR",
    }
    if normalized.lower() in simple_commands:
        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type=simple_commands[normalized.lower()],
            args={},
        )

    tokens: List[str] = normalized.split(" ")
    first_token = tokens[0].lower()

    # Parse `scan --target <target> [--profile <profile>]` OR `scan <target> [profile]`
    if first_token == "scan" and len(tokens) >= 2:
        target = ""
        profile = "STANDARD_TCP_INTEL"
        if tokens[1] == "--target" and len(tokens) >= 3:
            target = tokens[2]
            if len(tokens) >= 5 and tokens[3] == "--profile":
                profile = tokens[4].upper()
        else:
            target = tokens[1]
            if len(tokens) >= 3:
                profile = tokens[2].upper()

        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type="SCAN_TARGET",
            args={"target": target, "profile": profile},
        )

    # Parse `ports --target <target>` OR `ports <target>`
    if first_token == "ports" and len(tokens) >= 2:
        target = tokens[2] if (tokens[1] == "--target" and len(tokens) >= 3) else tokens[1]
        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type="PORTS_TARGET",
            args={"target": target},
        )

    # Parse `investigate <finding_or_ip_or_question>`
    if first_token == "investigate" and len(tokens) >= 2:
        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type="INVESTIGATE",
            args={"query": " ".join(tokens[1:])},
        )

    # Parse `ai <question>` for direct terminal AI queries
    if first_token in ("ai", "ask") and len(tokens) >= 2:
        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type="AI_QUERY",
            args={"question": " ".join(tokens[1:])},
        )

    # Explicit `shell <cmd>` prefix strips `shell ` and runs the underlying command
    if first_token == "shell" and len(tokens) >= 2:
        shell_cmd = cmd[cmd.lower().find("shell") + 5 :].strip()
        return ValidatedCommand(
            raw=cmd,
            is_allowed=True,
            command_type="SYSTEM_SHELL",
            args={"shell_cmd": shell_cmd},
        )

    # Any other command typed by the engineer (e.g., nmap, ipconfig, ifconfig, ping, netstat, whoami, arp, curl, etc.)
    # executes directly in the system shell
    return ValidatedCommand(
        raw=cmd,
        is_allowed=True,
        command_type="SYSTEM_SHELL",
        args={"shell_cmd": cmd},
    )
