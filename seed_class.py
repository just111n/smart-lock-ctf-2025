import random
import hashlib
import os
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Any, Optional
import time


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

    id:str = field(default_factory=lambda: str(int(time.time() * 1000)), compare=False)







