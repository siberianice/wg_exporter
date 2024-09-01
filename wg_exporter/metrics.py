import logging
import subprocess
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)

# Регулярные выражения
interface_pattern: Pattern[str] = re.compile(r'interface:\s*(\w+)')
peer_pattern: Pattern[str] = re.compile(r'peer:\s*([\w+/=]+)')
endpoint_pattern: Pattern[str] = re.compile(r'endpoint:\s*([\d.]+:\d+)')
handshake_pattern: Pattern[str] = re.compile(r'latest handshake:\s*(.+ ago)')
transfer_pattern: Pattern[str] = re.compile(r'transfer:\s*([\d.]+ \w+) received, ([\d.]+ \w+) sent')
byte_reading_pattern: Pattern[str] = re.compile(r'([\d.]+) (\w+)')

overrides: Dict[str, any] = {}

def override(key: str, value: any) -> None:
    overrides[key] = value

def run_command(command: List[str]) -> Optional[str]:
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.debug(f'Command output: {result.stdout}')
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {e}")
        return None

def parse_handshake_time(handshake: str) -> str:
    time_units = {
        'day': 3600 * 24,
        'hour': 3600,
        'minute': 60,
        'second': 1
    }
    seconds_ago = 0
    for unit, seconds in time_units.items():
        match = re.search(rf'(\d+)\s+{unit}', handshake)
        if match:
            seconds_ago += int(match.group(1)) * seconds

    current_time = overrides.get("override_current_time", datetime.now())
    target_time = current_time - timedelta(seconds=seconds_ago)
    return target_time.isoformat()

def parse_to_bytes(byte_reading: str) -> Optional[int]:
    match = byte_reading_pattern.search(byte_reading)
    if match:
        byte_size = match.group(1)
        indicator = match.group(2)
        multiplier = {
            "B": 1,
            "KiB": 1024**1,
            "MiB": 1024**2,
            "GiB": 1024**3,
            "TiB": 1024**4,
            "PiB": 1024**5
        }
        return int(float(byte_size) * multiplier.get(indicator, 1))
    return None

def parse_wg_output(wg_output: str) -> List[Dict[str, str]]:
    metrics: List[Dict[str, str]] = []

    interfaces_lines = split_lines_by_key("interface:", wg_output.splitlines())
    for interface_lines in interfaces_lines:
        interface_name = find_first(interface_pattern, interface_lines)
        if not interface_name:
            continue
        peers_lines = split_lines_by_key("peer:", interface_lines)
        for peer_lines in peers_lines:
            peer = find_first(peer_pattern, peer_lines)
            endpoint = find_first(endpoint_pattern, peer_lines)
            handshake = find_first(handshake_pattern, peer_lines)
            transfer = find_first_multiple_groups(transfer_pattern, peer_lines)
            if peer and endpoint and handshake and transfer:
                metrics.append({
                    "interface": interface_name,
                    "peer": peer,
                    "endpoint": endpoint,
                    "handshake": parse_handshake_time(handshake),
                    "rx_bytes": parse_to_bytes(transfer[0]) or 0,
                    "tx_bytes": parse_to_bytes(transfer[1]) or 0
                })

    logger.debug(f'Extracted metrics: {metrics}')
    return metrics

def find_first_multiple_groups(pattern: Pattern[str], lines: List[str]) -> Optional[List[str]]:
    for line in lines:
        match = re.search(pattern, line)
        if match:
            return list(match.groups())
    return None

def find_first(pattern: Pattern[str], lines: List[str]) -> Optional[str]:
    for line in lines:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None

def split_lines_by_key(split_key: str, lines: List[str]) -> List[List[str]]:
    indexes = [index for index, line in enumerate(lines) if split_key in line]
    return [lines[start:end] for start, end in zip(indexes, indexes[1:] + [None])]

def format_metrics(metrics: List[Dict[str, str]]) -> str:
    formatted_metrics = []
    for metric in metrics:
        formatted_metrics.append(
            f'wg_peer_info{{interface="{metric["interface"]}",peer="{metric["peer"]}",endpoint="{metric["endpoint"]}",last_handshake="{metric["handshake"]}"}} 1'
        )
        formatted_metrics.append(
            f'wg_peer_rx_bytes{{interface="{metric["interface"]}",peer="{metric["peer"]}"}} {metric["rx_bytes"]}'
        )
        formatted_metrics.append(
            f'wg_peer_tx_bytes{{interface="{metric["interface"]}",peer="{metric["peer"]}"}} {metric["tx_bytes"]}'
        )
    logger.debug(f'Formatted metrics: {formatted_metrics}')
    return '\n'.join(formatted_metrics)

def collect_metrics() -> str:
    wg_output = run_command(['sudo', 'wg', 'show'])
    if wg_output:
        metrics = parse_wg_output(wg_output)
        return format_metrics(metrics)
    else:
        return "Failed to retrieve WireGuard metrics."
