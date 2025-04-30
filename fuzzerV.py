#!/usr/bin/env python3
import sys
import asyncio
import random
import time
import heapq
import hashlib
import logging
import os
import argparse
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Any, Optional
from BLEClient import BLEClient

# Set up logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

timestamp = time.strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(log_dir, f"fuzzer_{timestamp}.log")
serial_log_file = os.path.join(log_dir, f"serial_logs_{timestamp}.txt")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Smart-Lock-Fuzzer")

# Setup serial log file
serial_logger = logging.getLogger("Serial-Log")
serial_handler = logging.FileHandler(serial_log_file)
serial_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
serial_logger.addHandler(serial_handler)
serial_logger.setLevel(logging.INFO)
serial_logger.propagate = False  # Don't send to root logger

# Device name - update this for your specific lock
DEVICE_NAME = "Smart Lock [Group 7]"  # Default device name, can be overridden

# Known commands from the specs
AUTH = [0x00]  # Authenticate command (needs passcode)
OPEN = [0x01]  # Open command
CLOSE = [0x02]  # Close command
DEFAULT_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Default passcode

# Response codes
RESPONSE_CODES = {
    0x00: "Success",
    0x01: "Authentication Failed",
    0x02: "Invalid Command",
    0x03: "Command Not Allowed (Not Authenticated)",
    0x04: "Lock Error (mechanical failure)"
}

# Define interesting test scenarios
INTERESTING_SCENARIOS = [
    # Basic protocol tests
    AUTH + DEFAULT_PASSCODE,  # Valid authentication
    OPEN,                     # Open command
    CLOSE,                    # Close command
    
    # State transition sequences
    AUTH + DEFAULT_PASSCODE + OPEN,  # Auth + Open
    AUTH + DEFAULT_PASSCODE + CLOSE, # Auth + Close
    
    # Command sequences in a single frame
    OPEN + CLOSE,            # Open then Close
    CLOSE + OPEN,            # Close then Open
    OPEN + OPEN,             # Open twice
    CLOSE + CLOSE,           # Close twice
    
    # Complex state transition sequences
    AUTH + DEFAULT_PASSCODE + OPEN + CLOSE, # Auth + Open + Close
    AUTH + DEFAULT_PASSCODE + CLOSE + OPEN, # Auth + Close + Open
    
    # Double authentication scenarios (potential bugs)
    AUTH + DEFAULT_PASSCODE + AUTH + DEFAULT_PASSCODE,
    
    # Full sequences
    AUTH + DEFAULT_PASSCODE + OPEN + CLOSE + OPEN + CLOSE,
    
    # Edge cases exploration
    [0x00],  # AUTH without passcode
    [0x03],  # Unknown command (off-by-one from CLOSE)
    [0xFF],  # Invalid command (maximum value)
    AUTH + DEFAULT_PASSCODE[:3],  # AUTH with incomplete passcode
]

@dataclass(order=True)
class SeedInput:
    """Represents a test input in the queue with priority for execution."""
    priority: float = field(compare=True)  # Lower values = higher priority
    energy: float = field(default=1.0, compare=False)  # Energy assigned to this input
    data: List[int] = field(default_factory=list, compare=False)  # The actual test data
    execution_count: int = field(default=0, compare=False)  # How many times it's been run
    path_hash: str = field(default="", compare=False)  # Hash of the execution path
    response: List[int] = field(default_factory=list, compare=False)  # Response from device
    interesting: bool = field(default=False, compare=False)  # Is this input interesting?
    error_detected: bool = field(default=False, compare=False)  # Did this input trigger an error?
    error_code: str = field(default="", compare=False)  # Error code if any


class PathTracker:
    """Tracks execution paths to identify new paths."""
    
    def __init__(self):
        self.known_paths: Set[str] = set()
        self.path_frequencies: Counter = Counter()
        self.path_weights: Dict[str, float] = {}
        self.error_paths: Dict[str, List[str]] = {}
        
    def is_new_path(self, path_hash: str) -> bool:
        """Check if this is a new path."""
        return path_hash not in self.known_paths
    
    def add_path(self, path_hash: str):
        """Add a path to known paths."""
        self.known_paths.add(path_hash)
        self.path_frequencies[path_hash] += 1
    
    def add_error_path(self, path_hash: str, error_code: str):
        """Add an error path with its error code."""
        if error_code not in self.error_paths:
            self.error_paths[error_code] = []
        self.error_paths[error_code].append(path_hash)
    
    def assign_path_weights(self):
        """Assign weights to paths based on frequency and potential interest."""
        # Initialize weights inversely proportional to frequency
        for path in self.known_paths:
            frequency = self.path_frequencies[path]
            # More rare paths get higher weights
            self.path_weights[path] = 1.0 / (frequency + 1)
            
            # Prioritize paths with error responses
            if path.startswith("ERROR"):
                self.path_weights[path] *= 3.0
                
            # Prioritize paths that indicate authentication bypasses
            if "AUTH_BYPASS" in path:
                self.path_weights[path] *= 2.0


class SmartLockFuzzer:
    """Main fuzzer class implementing AFL-style fuzzing for the Smart Lock."""
    
    def __init__(self, device_name: str, initial_seeds: List[List[int]]):
        self.device_name = device_name
        self.ble_client = BLEClient()
        self.path_tracker = PathTracker()
        
        # Priority queue for seeds
        self.seed_queue = []
        
        # Add initial seeds to queue
        for seed in initial_seeds:
            # Give complex command sequences higher priority
            priority = 0.5 if len(seed) > 2 else 1.0
            self._add_to_queue(seed, priority)
        
        # Track unique crashes observed
        self.unique_crashes = set()
        self.crash_inputs = {}  # Map error codes to inputs that caused them
        
        # Statistics
        self.total_executions = 0
        self.total_paths = 0
        self.total_crashes = 0
        self.start_time = time.time()
        self.last_reconnect_time = 0
        self.reconnect_counter = 0
        
        # Default energy function
        self.energy_function = self._inverse_energy
        
        # Known commands and valid states
        self.known_commands = {0x00, 0x01, 0x02}  # AUTH, OPEN, CLOSE
        
        # Mutation strategy weights - focus on command sequences rather than passcodes
        self.mutation_weights = {
            "command_focus": 0.8,      # Focus on command bytes and sequences
            "structure_focus": 0.15,   # Focus on structure (length, format)
            "passcode_focus": 0.05     # Minimal focus on passcode mutations
        }
    
    def _add_to_queue(self, data: List[int], priority: float = 1.0) -> SeedInput:
        """Add a new input to the seed queue."""
        seed = SeedInput(priority=priority, data=data)
        heapq.heappush(self.seed_queue, seed)
        return seed
    
    async def setup(self):
        """Set up the BLE client and serial port logs."""
        self.ble_client.init_logs()  # Initialize serial port logs collection
        logger.info(f"Connecting to {self.device_name}...")
        connected = await self.ble_client.connect(self.device_name)
        
        if not connected:
            logger.error(f"Failed to connect to {self.device_name}")
            return False
            
        logger.info(f"Successfully connected to {self.device_name}")
        
        # Send initial command 0x0a
        logger.info("Sending initial command 0x0a")
        res = await self.ble_client.write_command([0x0a])
        logger.info(f"Initial command response: {res}")
        
        return True
    
    async def reconnect(self):
        """Attempt to reconnect to the device after a crash."""
        now = time.time()
        # Limit reconnection attempts (max once every 5 seconds)
        if now - self.last_reconnect_time < 5:
            return False
            
        self.last_reconnect_time = now
        self.reconnect_counter += 1
        
        logger.info(f"Attempting to reconnect to {self.device_name} (attempt {self.reconnect_counter})...")
        
        try:
            # Close any existing connection
            await self.ble_client.disconnect()
            # Wait a moment for device to reset
            await asyncio.sleep(2)
            # Try to reconnect
            connected = await self.ble_client.connect(self.device_name)
            
            if connected:
                logger.info(f"Successfully reconnected to {self.device_name}")
                
                # Send initial command 0x0a after reconnection
                logger.info("Sending initial command 0x0a")
                res = await self.ble_client.write_command([0x0a])
                logger.info(f"Initial command response: {res}")
                
                return True
            else:
                logger.error(f"Failed to reconnect to {self.device_name}")
                return False
        except Exception as e:
            logger.error(f"Reconnection error: {str(e)}")
            return False
    
    async def teardown(self):
        """Clean up resources."""
        await self.ble_client.disconnect()
        self.ble_client.close_serialport()
    
    def choose_next(self) -> Optional[SeedInput]:
        """Choose the next input to test based on priority."""
        if not self.seed_queue:
            return None
        
        # Get the highest priority seed (lowest priority value)
        seed = heapq.heappop(self.seed_queue)
        seed.execution_count += 1
        
        # Re-compute energy based on execution count
        seed.energy = self.energy_function(seed.execution_count)
        
        return seed
    
    def _inverse_energy(self, count: int) -> float:
        """Inverse energy function: energy decreases with more executions."""
        return 1.0 / (count + 1)
    
    def _exponential_energy(self, count: int) -> float:
        """Exponential energy function: energy drops exponentially."""
        return 0.9 ** count
    
    def _linear_energy(self, count: int) -> float:
        """Linear energy function: energy drops linearly."""
        return max(0.1, 1.0 - (count * 0.1))
    
    def mutate_input(self, input_data: List[int]) -> List[int]:
        """Mutate the input data using various strategies, focusing on command sequences."""
        # Make a copy to avoid modifying the original
        data = input_data.copy()
        
        # Determine what kind of input we're dealing with
        is_auth_command = len(data) > 0 and data[0] == 0x00
        
        # Choose mutation focus based on weights
        focus = random.choices(
            ["command_focus", "structure_focus", "passcode_focus"],
            weights=[
                self.mutation_weights["command_focus"],
                self.mutation_weights["structure_focus"],
                self.mutation_weights["passcode_focus"]
            ],
            k=1
        )[0]
        
        if focus == "command_focus":
            # Focus on command bytes and command sequences
            strategy = random.choice([
                self._mutate_command_byte,
                self._add_command,
                self._combine_commands,
                self._sequence_commands,
                self._permute_commands,
                self._insert_adjacent_command,
            ])
            return strategy(data)
            
        elif focus == "structure_focus":
            # Focus on input structure (length, format)
            strategy = random.choice([
                self._delete_byte,
                self._insert_byte,
                self._duplicate_bytes,
                self._change_length,
            ])
            return strategy(data)
            
        else:  # passcode_focus
            # Only mutate passcode if this is an auth command
            if is_auth_command and len(data) > 1:
                # Choose a passcode mutation strategy
                strategy = random.choice([
                    self._byte_flip,
                    self._random_byte,
                    self._overwrite_byte
                ])
                return strategy(data)
            else:
                # Fall back to command focus for non-auth commands
                return self._mutate_command_byte(data)
        
        # Fallback in case no mutation applied
        return self._random_byte(data)
    
    def _mutate_command_byte(self, data: List[int]) -> List[int]:
        """Mutate the command byte (first byte) in various ways."""
        if not data:
            return [random.choice([0x00, 0x01, 0x02, 0x03, 0xFF])]
            
        # If it's an AUTH command, keep the passcode part
        passcode_part = data[1:] if data[0] == 0x00 and len(data) > 1 else []
        
        # Choose a mutation type
        mutation_type = random.choice(["bit_flip", "adjacent", "random"])
        
        if mutation_type == "bit_flip":
            # Flip a random bit in the command byte
            bit_pos = random.randint(0, 7)
            new_cmd = data[0] ^ (1 << bit_pos)
        elif mutation_type == "adjacent":
            # Use a command value adjacent to known commands
            base_cmd = random.choice([0x00, 0x01, 0x02])
            offset = random.choice([-2, -1, 1, 2])
            new_cmd = (base_cmd + offset) % 256
        else:  # random
            # Use a completely random command
            new_cmd = random.randint(0, 255)
        
        # If we selected AUTH (0x00), make sure it has a passcode
        if new_cmd == 0x00 and not passcode_part:
            return [new_cmd] + DEFAULT_PASSCODE
        
        # If it was AUTH and now it's not, drop the passcode
        if data[0] == 0x00 and new_cmd != 0x00:
            return [new_cmd]
        
        # If it wasn't AUTH and still isn't, just replace the command
        if data[0] != 0x00 and new_cmd != 0x00:
            return [new_cmd]
        
        # Otherwise, keep the structure
        return [new_cmd] + passcode_part
    
    def _add_command(self, data: List[int]) -> List[int]:
        """Add a random command after the existing command."""
        # Choose a random command to add
        cmd = random.choice([0x00, 0x01, 0x02, 0x03, 0xFF])
        
        if cmd == 0x00:  # AUTH needs a passcode
            return data + [cmd] + DEFAULT_PASSCODE
        else:
            return data + [cmd]
    
    def _combine_commands(self, data: List[int]) -> List[int]:
        """Combine multiple commands into a single input sequence."""
        result = data.copy()
        
        # Add 1-3 additional commands
        for _ in range(random.randint(1, 3)):
            cmd = random.choice([0x00, 0x01, 0x02])
            
            if cmd == 0x00:  # AUTH command needs passcode
                result += [cmd] + DEFAULT_PASSCODE
            else:
                result += [cmd]
        
        return result
    
    def _sequence_commands(self, data: List[int]) -> List[int]:
        """Create a sequence of known commands."""
        sequence = []
        
        # Choose 2-4 commands to sequence
        for _ in range(random.randint(2, 4)):
            cmd = random.choice([0x00, 0x01, 0x02])
            
            if cmd == 0x00:
                sequence.extend([cmd] + DEFAULT_PASSCODE)
            else:
                sequence.append(cmd)
        
        return sequence
    
    def _permute_commands(self, data: List[int]) -> List[int]:
        """Create a permutation of OPEN and CLOSE commands."""
        # Start with an authentication if needed
        if random.random() < 0.7:
            result = [0x00] + DEFAULT_PASSCODE
        else:
            result = []
        
        # Add a permutation of OPEN/CLOSE commands
        num_commands = random.randint(2, 5)
        for _ in range(num_commands):
            result.append(random.choice([0x01, 0x02]))
        
        return result
    
    def _insert_adjacent_command(self, data: List[int]) -> List[int]:
        """Insert a command that is numerically adjacent to a known command."""
        # Pick a base command
        base_cmd = random.choice([0x00, 0x01, 0x02])
        
        # Generate an adjacent value (-2 to +2)
        offset = random.choice([-2, -1, 1, 2])
        adjacent_cmd = (base_cmd + offset) % 256
        
        # Insert it at a random position
        pos = random.randint(0, len(data))
        
        return data[:pos] + [adjacent_cmd] + data[pos:]
    
    def _bit_flip_byte(self, byte_value: int) -> int:
        """Flip a random bit in a byte."""
        bit_pos = random.randint(0, 7)
        return byte_value ^ (1 << bit_pos)  # XOR to flip the bit
    
    def _bit_flip(self, data: List[int]) -> List[int]:
        """Flip a random bit in the input."""
        if not data:
            return data
            
        pos = random.randint(0, len(data) - 1)
        data[pos] = self._bit_flip_byte(data[pos])
        return data
    
    def _byte_flip(self, data: List[int]) -> List[int]:
        """Flip a random byte (invert all bits)."""
        if not data:
            return data
            
        pos = random.randint(0, len(data) - 1)
        data[pos] = 0xFF - data[pos]  # Invert all bits
        return data
    
    def _random_byte(self, data: List[int]) -> List[int]:
        """Replace a byte with a random value."""
        if not data:
            return data
            
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
        return data
    
    def _delete_byte(self, data: List[int]) -> List[int]:
        """Delete a random byte."""
        if not data:
            return data
            
        if len(data) > 1:  # Don't delete if only one byte left
            pos = random.randint(0, len(data) - 1)
            return data[:pos] + data[pos+1:]
        return data
    
    def _insert_byte(self, data: List[int]) -> List[int]:
        """Insert a random byte at a random position."""
        pos = random.randint(0, len(data))
        return data[:pos] + [random.randint(0, 255)] + data[pos:]
    
    def _duplicate_bytes(self, data: List[int]) -> List[int]:
        """Duplicate part of the input."""
        if not data:
            return data
            
        if len(data) >= 1:
            # Select a segment to duplicate
            start = random.randint(0, len(data) - 1)
            length = random.randint(1, min(3, len(data) - start))
            segment = data[start:start+length]
            
            # Insert the duplicate segment
            insert_pos = random.randint(0, len(data))
            return data[:insert_pos] + segment + data[insert_pos:]
        return data
    
    def _change_length(self, data: List[int]) -> List[int]:
        """Change the length of the input (grow or shrink)."""
        if not data:
            return [random.randint(0, 255)]
            
        if random.random() < 0.5 and len(data) > 1:
            # Shrink: remove a random chunk
            start = random.randint(0, len(data) - 1)
            length = random.randint(1, min(3, len(data) - start))
            return data[:start] + data[start+length:]
        else:
            # Grow: add random bytes
            num_bytes = random.randint(1, 5)
            new_bytes = [random.randint(0, 255) for _ in range(num_bytes)]
            pos = random.randint(0, len(data))
            return data[:pos] + new_bytes + data[pos:]
    
    def _overwrite_byte(self, data: List[int]) -> List[int]:
        """Overwrite a segment with random bytes."""
        if not data:
            return data
            
        if len(data) >= 2:
            start = random.randint(0, len(data) - 1)
            length = random.randint(1, min(3, len(data) - start))
            for i in range(length):
                data[start + i] = random.randint(0, 255)
        else:
            data[0] = random.randint(0, 255)
        return data
    
    def log_serial_output(self, logs: List[str], command: List[int]):
        """Log all serial output to a dedicated file with the command that triggered it."""
        cmd_str = ', '.join([f'0x{byte:02X}' for byte in command])
        serial_logger.info(f"Command: [{cmd_str}]")
        
        for log_line in logs:
            serial_logger.info(f"  {log_line}")
        
        serial_logger.info("-" * 50)
    
    def compute_path_hash(self, logs: List[str], response: List[int]) -> str:
        """Compute a hash to identify the execution path."""
        # Extract important events from logs
        path_events = []
        is_error = False
        error_code = ""
        
        for log_line in logs:
            # Capture key state transitions or events
            if "[State]" in log_line:
                path_events.append(log_line.strip())
            elif "[Error]" in log_line:
                is_error = True
                path_events.append(log_line.strip())
                if "Code:" in log_line:
                    error_code = log_line.split("Code:")[1].strip()
            elif "[Auth]" in log_line:
                path_events.append(log_line.strip())
            elif "[Bluetooth]" in log_line and "Received command" in log_line:
                path_events.append(log_line.strip())
        
        # Add the response to the path
        path_events.append(f"Response:{response}")
        
        # Create a hash of the path
        path_str = "||".join(path_events)
        path_hash = hashlib.md5(path_str.encode()).hexdigest()
        
        # For error paths, prefix the hash with ERROR to prioritize them
        if is_error:
            return f"ERROR:{error_code}:{path_hash}"
        
        # For paths that might indicate authentication bypass
        if any("Authenticated" in event for event in path_events) and \
           not any("[Auth] Authentication successful" in event for event in path_events):
            return f"AUTH_BYPASS:{path_hash}"
            
        return path_hash
    
    def extract_error_code(self, logs: List[str]) -> Tuple[bool, str]:
        """Extract error code from logs if present."""
        for log_line in logs:
            if "[Error]" in log_line and "Code:" in log_line:
                try:
                    error_code = log_line.split("Code:")[1].strip()
                    return True, error_code
                except IndexError:
                    return True, "Unknown"
        return False, ""
    
    def is_interesting(self, seed: SeedInput, logs: List[str], response: List[int]) -> bool:
        """Determine if this input is interesting based on path or response."""
        # Update the seed with response
        seed.response = response
        
        # Check if it's a crash and extract error code
        is_error, error_code = self.extract_error_code(logs)
        seed.error_detected = is_error
        seed.error_code = error_code
        
        # Compute path hash for this execution
        path_hash = self.compute_path_hash(logs, response)
        seed.path_hash = path_hash
        
        # Log all serial output with the command that triggered it
        self.log_serial_output(logs, seed.data)
        
        # Check if it's a crash
        if is_error:
            crash_sig = f"{path_hash}:{error_code}"
            
            if crash_sig not in self.unique_crashes:
                self.unique_crashes.add(crash_sig)
                self.total_crashes += 1
                self.crash_inputs[error_code] = seed.data.copy()  # Store the input that caused this crash
                
                cmd_str = ', '.join([f'0x{byte:02X}' for byte in seed.data])
                
                logger.warning(f"NEW CRASH FOUND! Error code: {error_code}")
                logger.warning(f"Input that caused crash: [{cmd_str}]")
                
                # Save crash to a dedicated file
                crash_dir = "crashes"
                os.makedirs(crash_dir, exist_ok=True)
                crash_file = os.path.join(crash_dir, f"crash_{error_code}_{timestamp}.txt")
                
                with open(crash_file, 'w') as f:
                    f.write(f"Error Code: {error_code}\n")
                    f.write(f"Command: [{cmd_str}]\n")
                    f.write(f"Response: {response}\n\n")
                    f.write("Serial Logs:\n")
                    for log_line in logs:
                        f.write(f"{log_line}\n")
                    f.write("\nReproduction code:\n")
                    f.write("```python\n")
                    f.write("from BLEClient import BLEClient\n")
                    f.write("ble = BLEClient()\n")
                    f.write("ble.init_logs()\n")
                    f.write(f"await ble.connect(\"{self.device_name}\")\n")
                    f.write(f"response = await ble.write_command({seed.data})\n")
                    f.write("print(response)\n")
                    f.write("logs = ble.read_logs()\n")
                    f.write("for log in logs:\n")
                    f.write("    print(log)\n")
                    f.write("```\n")
                
                return True
        
        # Check if it's a new path (even if not a crash)
        if self.path_tracker.is_new_path(path_hash):
            self.path_tracker.add_path(path_hash)
            
            # For error paths, also track by error code
            if is_error:
                self.path_tracker.add_error_path(path_hash, error_code)
                
            self.total_paths += 1
            
            # Output for interesting non-crash paths
            if not is_error:
                cmd_str = ', '.join([f'0x{byte:02X}' for byte in seed.data])
                resp_str = ', '.join([f'0x{byte:02X}' for byte in response]) if response else "No response"
                
                logger.info(f"NEW PATH FOUND: {path_hash[:8]}...")
                logger.info(f"Input: [{cmd_str}], Response: [{resp_str}]")
            
            return True
        
        # Not interesting, but update path frequency
        self.path_tracker.path_frequencies[path_hash] += 1
        return False
    
    def assign_energy(self, seed: SeedInput) -> float:
        """Assign energy to a seed based on how promising it seems."""
        # Start with the base energy
        energy = seed.energy
        
        # Adjust energy based on path weight if available
        if seed.path_hash in self.path_tracker.path_weights:
            path_weight = self.path_tracker.path_weights[seed.path_hash]
            energy *= path_weight
        
        # Seeds that led to crashes get extra energy
        if seed.error_detected:
            energy *= 3.0
        
        # Seeds with error response codes get extra energy
        if seed.response and seed.response[0] != 0:
            energy *= 1.5
        
        # Prioritize complex command sequences
        if len(seed.data) > 2:
            energy *= 1.2
            
        return energy
    
    async def execute_input(self, input_data: List[int]) -> Tuple[List[str], List[int]]:
        """Execute a test input against the Smart Lock."""
        try:
            # Clear previous logs
            self.ble_client.serialport_logs = []
            
            # Send the command to the device
            cmd_str = ', '.join([f'0x{byte:02X}' for byte in input_data])
            logger.info(f"Testing input: [{cmd_str}]")
            
            response = await self.ble_client.write_command(input_data)
            
            # Collect logs
            logs = self.ble_client.read_logs()
            
            # Check for interesting error logs
            for log in logs:
                if "[Error]" in log:
                    logger.warning(f"Error detected: {log}")
                elif "[State]" in log:
                    logger.info(f"State change: {log}")
                elif "[Auth]" in log:
                    logger.info(f"Auth event: {log}")
            
            return logs, response
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error executing input {input_data}: {error_msg}")
            
            # Special handling for disconnection errors
            if "disconnected" in error_msg.lower() or "Discovery" in error_msg:
                # Add the device crashed log line to help identify the error
                return ["[Error] Device crashed or disconnected", f"[Error] Code: CRASH-DISCONNECT"], []
            
            return [f"[Error] Execution failed: {error_msg}"], []
    
    def assign_path_weights(self):
        """Assign weights to paths for prioritization."""
        self.path_tracker.assign_path_weights()
    
    def print_stats(self):
        """Print fuzzing statistics."""
        elapsed = time.time() - self.start_time
        executions_per_second = self.total_executions / elapsed if elapsed > 0 else 0
        
        logger.info("=" * 60)
        logger.info("Fuzzing Statistics:")
        logger.info(f"Runtime: {elapsed:.2f} seconds")
        logger.info(f"Total executions: {self.total_executions}")
        logger.info(f"Executions/sec: {executions_per_second:.2f}")
        logger.info(f"Unique paths: {self.total_paths}")
        logger.info(f"Unique crashes: {self.total_crashes}")
        logger.info(f"Queue size: {len(self.seed_queue)}")
        logger.info("=" * 60)
    
    async def fuzz(self, max_iterations: int = 1000, timeout_sec: int = 1800):
        """Run the main fuzzing loop."""
        try:
            success = await self.setup()
            if not success:
                logger.error("Failed to set up the fuzzer. Exiting.")
                return
            
            logger.info(f"Starting fuzzing of {self.device_name} for {max_iterations} iterations or {timeout_sec} seconds")
            
            iteration = 0
            start_time = time.time()
            
            # First, run the interesting scenarios to establish baseline paths
            logger.info("Testing interesting scenarios first...")
            for i, scenario in enumerate(INTERESTING_SCENARIOS):
                cmd_str = ', '.join([f'0x{byte:02X}' for byte in scenario])
                logger.info(f"Testing scenario {i+1}: [{cmd_str}]")
                
                logs, response = await self.execute_input(scenario)
                seed = SeedInput(priority=0.5, data=scenario.copy(), response=response)
                
                if self.is_interesting(seed, logs, response):
                    # If it's interesting, add it back to the queue
                    energy = self.assign_energy(seed)
                    seed.energy = energy
                    seed.priority = -energy  # Negative for max-heap
                    heapq.heappush(self.seed_queue, seed)
                
                # Give the device a moment to recover
                await asyncio.sleep(0.5)
            
            logger.info("Continuing with fuzzing...")
            
            while (iteration < max_iterations and 
                  time.time() - start_time < timeout_sec):
                
                if iteration % 20 == 0:
                    self.print_stats()
                
                # Get the next seed to test
                current_seed = self.choose_next()
                if not current_seed:
                    logger.warning("Seed queue is empty! Adding default seeds.")
                    # Add basic commands back to the queue
                    for seed in INTERESTING_SCENARIOS[:5]:  # Just add the first few basic ones
                        self._add_to_queue(seed, priority=0.5)
                    continue
                
                # Execute the seed as-is first to establish baseline
                if current_seed.execution_count <= 1:
                    cmd_str = ', '.join([f'0x{byte:02X}' for byte in current_seed.data])
                    logger.info(f"Testing original seed: [{cmd_str}]")
                    
                    logs, response = await self.execute_input(current_seed.data)
                    
                    # Check if it's interesting
                    interesting = self.is_interesting(current_seed, logs, response)
                    current_seed.interesting = interesting
                    
                    if interesting:
                        # Re-add to queue with updated priority
                        energy = self.assign_energy(current_seed)
                        current_seed.energy = energy
                        current_seed.priority = -energy  # Negative for max-heap behavior
                        heapq.heappush(self.seed_queue, current_seed)
                
                # Check if we need to reconnect due to a potential crash
                if any("disconnected" in log.lower() for log in self.ble_client.read_logs()):
                    logger.warning("Device appears to be disconnected. Attempting to reconnect...")
                    reconnected = await self.reconnect()
                    if not reconnected:
                        logger.error("Failed to reconnect. Exiting fuzzing loop.")
                        break
                    continue  # Skip this iteration and go to the next
                
                # Generate mutated inputs based on energy
                num_mutations = max(1, int(current_seed.energy * 3))
                
                for _ in range(num_mutations):
                    # Create mutated input
                    mutated_data = self.mutate_input(current_seed.data)
                    
                    # Skip empty commands
                    if not mutated_data:
                        continue
                    
                    # Execute the mutated input
                    logs, response = await self.execute_input(mutated_data)
                    
                    # Create a seed object for this input
                    mutated_seed = SeedInput(
                        priority=1.0,
                        data=mutated_data.copy(),
                        response=response
                    )
                    
                    # Check if it's interesting
                    interesting = self.is_interesting(mutated_seed, logs, response)
                    
                    if interesting:
                        # Calculate energy and add to queue
                        energy = self.assign_energy(mutated_seed)
                        mutated_seed.energy = energy
                        mutated_seed.priority = -energy  # Negative for max-heap
                        mutated_seed.interesting = True
                        heapq.heappush(self.seed_queue, mutated_seed)
                    
                    # Check if we need to reconnect after this test
                    if any("disconnected" in log.lower() for log in logs):
                        logger.warning("Device appears to be disconnected after test. Attempting to reconnect...")
                        reconnected = await self.reconnect()
                        if not reconnected:
                            logger.error("Failed to reconnect. Exiting mutation loop.")
                            break
                        break  # Break the mutation loop and move to the next seed
                
                # Reassign weights periodically based on what we've learned
                if iteration % 10 == 0:
                    self.assign_path_weights()
                
                iteration += 1
                self.total_executions += 1
                
                # Small delay to avoid overwhelming the device
                await asyncio.sleep(0.2)
            
            logger.info("Fuzzing complete!")
            
            # Print crash summary
            if self.total_crashes > 0:
                logger.info(f"Found {self.total_crashes} unique crashes:")
                for i, crash_sig in enumerate(self.unique_crashes):
                    parts = crash_sig.split(':')
                    if len(parts) >= 2:
                        error_code = parts[1]
                        logger.info(f"  {i+1}. Error code: {error_code}")
                        
                        # Print the input that caused this crash if available
                        if error_code in self.crash_inputs:
                            cmd = self.crash_inputs[error_code]
                            cmd_str = ', '.join([f'0x{byte:02X}' for byte in cmd])
                            logger.info(f"     Command: [{cmd_str}]")
                            
                            # Print reproduction code
                            logger.info(f"     To reproduce: ")
                            logger.info(f"     await ble.connect(\"{self.device_name}\")")
                            logger.info(f"     response = await ble.write_command({cmd})")
            else:
                logger.info("No crashes found.")
            
            self.print_stats()
                
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user.")
        except Exception as e:
            logger.error(f"Error during fuzzing: {str(e)}")
        finally:
            await self.teardown()


async def run_directed_tests(device_name: str):
    """Run predefined test scenarios known to trigger specific behaviors."""
    ble = BLEClient()
    ble.init_logs()
    
    # Define key test scenarios that are likely to trigger bugs
    test_scenarios = [
        # Basic functionality tests
        (AUTH + DEFAULT_PASSCODE, "Basic authentication"),
        (OPEN, "Open without authentication"),
        (CLOSE, "Close without authentication"),
        
        # Command sequences
        (AUTH + DEFAULT_PASSCODE + OPEN, "Auth + Open"),
        (AUTH + DEFAULT_PASSCODE + CLOSE, "Auth + Close"),
        
        # Command combinations that might trigger bugs
        (OPEN + CLOSE, "Open+Close combined"),
        (CLOSE + OPEN, "Close+Open combined"),
        (AUTH + DEFAULT_PASSCODE + OPEN + CLOSE, "Auth+Open+Close"),
        (AUTH + DEFAULT_PASSCODE + AUTH + DEFAULT_PASSCODE, "Double authentication"),
        
        # Edge cases
        ([0x03], "Unknown command (0x03)"),
        ([0xFF], "Unknown command (0xFF)"),
        ([0x00], "AUTH without passcode"),
        (AUTH + DEFAULT_PASSCODE[:3], "AUTH with partial passcode"),
        
        # Repetitive commands
        ([0x01, 0x01, 0x01], "Multiple OPENs"),
        ([0x02, 0x02, 0x02], "Multiple CLOSEs"),
        ([0x01, 0x02, 0x01, 0x02], "Alternating OPEN/CLOSE"),
        
        # Mixed command sequences
        (AUTH + DEFAULT_PASSCODE + [0x01, 0x02, 0x01, 0x02], "AUTH + alternating OPEN/CLOSE"),
        (AUTH + DEFAULT_PASSCODE + [0xFF, 0x01], "AUTH + invalid command + OPEN"),
        (AUTH + DEFAULT_PASSCODE + [0x03, 0x01], "AUTH + unknown command + OPEN"),
        
        # Special command 0x0a test
        ([0x0a], "Command 0x0a"),
        ([0x0a, 0x0a], "Double command 0x0a"),
        (AUTH + DEFAULT_PASSCODE + [0x0a], "AUTH + command 0x0a"),
        ([0x0a] + AUTH + DEFAULT_PASSCODE, "Command 0x0a + AUTH"),
    ]
    
    try:
        logger.info(f"Connecting to {device_name}...")
        connected = await ble.connect(device_name)
        
        if not connected:
            logger.error(f"Failed to connect to {device_name}")
            return
            
        # Send initial command 0x0a
        logger.info("Sending initial command 0x0a")
        res = await ble.write_command([0x0a])
        logger.info(f"Initial command response: {res}")
            
        logger.info(f"Running directed tests against {device_name}...")
        
        # Track found error codes
        error_codes_found = set()
        
        for i, (test_cmd, description) in enumerate(test_scenarios):
            cmd_str = ', '.join([f'0x{byte:02X}' for byte in test_cmd])
            logger.info(f"Test {i+1}/{len(test_scenarios)}: {description}")
            logger.info(f"Command: [{cmd_str}]")
            
            try:
                # Clear previous logs
                ble.serialport_logs = []
                
                # Send the command
                response = await ble.write_command(test_cmd)
                response_desc = RESPONSE_CODES.get(response[0], "Unknown") if response else "No response"
                logger.info(f"Response: {response} ({response_desc})")
                
                # Get and analyze logs
                logs = ble.read_logs()
                
                # Check for errors in logs
                for log in logs:
                    if "[Error]" in log:
                        logger.warning(f"Error detected: {log}")
                        if "Code:" in log:
                            error_code = log.split("Code:")[1].strip()
                            error_codes_found.add(error_code)
                            logger.warning(f"Found error code: {error_code}")
                    else:
                        logger.debug(f"Log: {log}")
                
                # Save results to a file if it's interesting
                if response and response[0] != 0x00 or any("[Error]" in log for log in logs):
                    scenario_file = f"directed_test_{i+1}_{description.replace(' ', '_')}.txt"
                    with open(scenario_file, "w") as f:
                        f.write(f"Test: {description}\n")
                        f.write(f"Command: [{cmd_str}]\n")
                        f.write(f"Response: {response} ({response_desc})\n\n")
                        f.write("Logs:\n")
                        for log in logs:
                            f.write(f"{log}\n")
                        
                        # Add reproduction code
                        f.write("\nReproduction code:\n")
                        f.write("```python\n")
                        f.write("from BLEClient import BLEClient\n")
                        f.write("ble = BLEClient()\n")
                        f.write("ble.init_logs()\n")
                        f.write(f"await ble.connect(\"{device_name}\")\n")
                        f.write(f"response = await ble.write_command({test_cmd})\n")
                        f.write("print(response)\n")
                        f.write("logs = ble.read_logs()\n")
                        f.write("for log in logs:\n")
                        f.write("    print(log)\n")
                        f.write("```\n")
                
            except Exception as e:
                logger.error(f"Error testing scenario {description}: {str(e)}")
            
            # Wait a bit between tests
            await asyncio.sleep(1)
            
            # Try to reconnect if needed
            if not ble.client or not ble.client.is_connected:
                logger.warning("Device disconnected. Attempting to reconnect...")
                await asyncio.sleep(3)  # Give device time to reset
                await ble.connect(device_name)
                await asyncio.sleep(1)
        
        # Print summary of findings
        logger.info("=" * 60)
        logger.info("Directed Testing Complete")
        logger.info(f"Found {len(error_codes_found)} unique error codes:")
        for code in error_codes_found:
            logger.info(f"  - {code}")
        logger.info("=" * 60)
    
    except Exception as e:
        logger.error(f"Error during directed testing: {str(e)}")
    finally:
        await ble.disconnect()
        ble.close_serialport()


async def main():
    """Main entry point for the fuzzer."""
    parser = argparse.ArgumentParser(description='Smart Lock Fuzzer')
    parser.add_argument('--device', '-d', default=DEVICE_NAME, 
                        help=f'BLE device name (default: {DEVICE_NAME})')
    parser.add_argument('--iterations', '-i', type=int, default=1000,
                        help='Maximum number of fuzzing iterations (default: 1000)')
    parser.add_argument('--timeout', '-t', type=int, default=1800,
                        help='Maximum runtime in seconds (default: 1800)')
    parser.add_argument('--directed', action='store_true',
                        help='Run directed tests instead of fuzzing')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        default='INFO', help='Set the logging level')
    
    # Allow passing iterations as positional argument
    parser.add_argument('iterations_pos', nargs='?', type=int, 
                        help='Maximum iterations (alternative to --iterations)')
    
    # Allow passing device name as second positional argument
    parser.add_argument('device_pos', nargs='?', 
                        help='BLE device name (alternative to --device)')
    
    args = parser.parse_args()
    
    # Set logging level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Use positional arguments if provided
    iterations = args.iterations_pos if args.iterations_pos is not None else args.iterations
    device_name = args.device_pos if args.device_pos is not None else args.device
    
    # Run directed tests if requested
    if args.directed:
        logger.info(f"Running directed tests against {device_name}")
        await run_directed_tests(device_name)
        return
    
    # Create and run the fuzzer with the interesting scenarios as initial seeds
    fuzzer = SmartLockFuzzer(device_name, INTERESTING_SCENARIOS)
    await fuzzer.fuzz(iterations, args.timeout)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")