import random
import hashlib
import os
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Any, Optional
import time

def generate_invalid_commands():
    return [
        [random.randint(0, 255)],  # Single random byte
        [random.randint(0, 255) for _ in range(2)],
        [random.randint(0, 255) for _ in range(3)],
        [random.randint(0, 255) for _ in range(10)],
        [0x01],  # OPEN
        [0x01, 0x02],  # OPEN + CLOSE
    ]

def load_existing_crash_hashes(folder="crashes"):
    crash_hashes = set()
    for fname in os.listdir(folder):
        if fname.endswith(".txt"):  # Only read text-format saved crashes
            path = os.path.join(folder, fname)
            with open(path, "r") as f:
                content = f.read().strip()
                # Normalize spacing, remove brackets, etc. to hash consistently
                normalized = content.replace("[", "").replace("]", "").replace(",", "").replace(" ", "")
                crash_hashes.add(hashlib.md5(normalized.encode()).hexdigest())
    return crash_hashes

@dataclass(order=True)
class Seed:
    """Represents a test input in the BLE fuzzing queue."""
    priority: float = field(compare=True)  # Lower = higher priority
    energy: float = field(default=1.0, compare=False)
    data: List[List[int]] = field(default_factory=[], compare=False)
    execution_count: int = field(default=0, compare=False)
    path_hash: str = field(default="", compare=False)
    response: bytes = field(default_factory=bytes, compare=False)
    response_hash: str = field(default="", compare=False)
    is_interesting: bool = field(default=False, compare=False)
    is_error_detected: bool = field(default=False, compare=False)
    error_code: Any = field(default="", compare=False)
    timestamp: float = field(default_factory=time.time, compare=False)
    parent_hash: Optional[str] = field(default="", compare=False)
    mutation_note: str = field(default="", compare=False)
    logs: List[str] = field(default_factory=list, compare=False)  # BLE comms/debug logs
    number_of_commands_executed: int = field(default=0, compare=False)  # Number of commands executed in this seed




def create_seed_from_command(data: List[List[int]], note: str = "") -> Seed:
    """
    Create a Seed from a 2D BLE command sequence.
    - Each command is a list of bytes.
    - The whole sequence is a list of such commands.
    """

    # Flatten the 2D command list into a 1D byte sequence
    flattened = []
    for cmd in data:
        flattened.extend(cmd)

    flat_bytes = bytes(flattened)

    # Compute path hash from the command sequence only (no response yet)
    path_hash = hashlib.sha256(flat_bytes).hexdigest()

    return Seed(
        priority=0.1,
        energy=1.0,
        data=data,
        path_hash=path_hash,
        mutation_note=note,
        logs=[f"Generated from DEFAULT_COMMAND_SEQUENCES at {time.ctime()}"]
    )



def inverse_energy(count: int) -> float:
        """Inverse energy function: energy decreases with more executions."""
        return 1.0 / (count + 1)
    
def exponential_energy(count: int) -> float:
    """Exponential energy function: energy drops exponentially."""
    return 0.9 ** count
    
def linear_energy(count: int) -> float:
    """Linear energy function: energy drops linearly."""
    return max(0.1, 1.0 - (count * 0.1))


