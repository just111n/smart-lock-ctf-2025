import asyncio
import hashlib
import heapq
import os
import random
import time
from typing import List, Optional, Set, Tuple,Dict
import sys

from BLEClient import BLEClient
from seed_class import Seed
from afl_fuzzer_abstract_class import AFLFuzzer  

# === Constants ===
DEVICE_NAME = "Smart Lock [Group 7]"
CRASH_DIR = "crashes"
INTERESTING_DIR = "interesting"
NUMBER_OF_SEEDS_TESTED = 100


# === Commands ===
AUTH = [0x00]
OPEN = [0x01]
CLOSE = [0x02]
DEFAULT_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
WRONG_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07]

EXPECTED_RESPONSES = [[0x00], [0x01], [0x02], [0x03], [0x04]]

SEED_COMMAND_SEQUENCES:List[List[List[int]]] = [


    # [AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  AUTH+WRONG_PASSCODE,
    #  OPEN,OPEN,OPEN],

    # # tttttt
    #  [[0xFF] * 8,[0xFF] * 8],

    # # 001675
    # [AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,
    #  AUTH+DEFAULT_PASSCODE,],

    #  # s7a8dj
    #  [[0x03, 0x7D, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C, 0x8C, 0x2C],
    #  [0x03, 0x7D, 0x7D, 0x8C, 0x2C, 0x8C, 0x2C],],

    #  # 010203
    #  [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07],[0x01],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07],
    #  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07],[0x01],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07],],

    #  # ASDJH$
    #  [[0x01] * 256],

    #  # asnmdb
    #  [[0xAA,0xAA ],
    #  OPEN,[0xAA,0xAA ],
    #  OPEN,[0xAA,0xAA ],
    #  OPEN],

    #  # 3948472
    # [ [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
    # [ 0x01, 0x02],[ 0x01, 0x02],[ 0x01, 0x02],[ 0x01, 0x02]],

     

    #  # ??????
    #  [[0x3F,0x3F,0x3F,0x3F,0x3F]],

    #  # KSMS&H
    #  [[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0xCF,0xCF]],


    #  # 018374
    #  [[0x00]*255,
    #  AUTH+DEFAULT_PASSCODE,[0x00]*255,
    #  AUTH+DEFAULT_PASSCODE,],

    #  # disable servo
    #  [[0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A]],

     # enable servo
     [[0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B]],


]

# HELPER FUNCTIONS
def save_to(folder: str, seed:Seed, ble_last_log:str) -> None:
    """
    Save the seed's data into a structured folder by parent hash.
    """
    # os.makedirs(folder, exist_ok=True)

    parent_folder = seed.parent_hash or "initial_seed"
    full_folder_path = os.path.join(folder, parent_folder)
    os.makedirs(full_folder_path, exist_ok=True)

    # Generate filename from flattened command hex
    filename = f"{seed.path_hash}.txt"
    path = os.path.join(full_folder_path, filename)

    print(f"Saving to {path}")

    with open(path, "w", encoding="utf-8") as f:

        f.write(f"=== Seed Data ===\n")

        # Write the raw 2D command data
        f.write(f"\n--- 2D Command Sequence ---\n")
        for i, cmd in enumerate(seed.data):
            hex_cmd = ", ".join(f"0x{b:02X}" for b in cmd)
            f.write(f"[{hex_cmd}],")

        f.write(f"\n")

        f.write("\n--- BLE Log ---\n")
        
        f.write(ble_last_log + "\n")

        f.write(f"=== Fuzzed BLE Input ===\n")
        f.write(f"Timestamp       : {time.ctime(seed.timestamp)}\n")
        f.write(f"Execution Count : {seed.execution_count}\n")
        f.write(f"Priority        : {seed.priority:.4f}\n")
        f.write(f"Energy          : {seed.energy:.4f}\n")
        f.write(f"Mutation Note   : {seed.mutation_note}\n")
        f.write(f"Parent Hash     : {seed.parent_hash}\n")
        f.write(f"Path Hash       : {seed.path_hash}\n")
        f.write(f"Error Detected  : {seed.is_error_detected}\n")
        f.write(f"Error Code      : {seed.error_code}\n")
        f.write(f"Response        : {[f'0x{b:02X}' for b in seed.response]}\n")
        f.write(f"Response Hash   : {seed.response_hash}\n")
        f.write(f"number_of_commands_executed: {seed.number_of_commands_executed}\n")
        f.write(f"Is all commands executed: {seed.is_all_commands_executed}\n")
        f.write(f"Is Seed Interesting: {seed.is_interesting}\n")
        
      

        f.write("\n--- Seed Logs ---\n")
        for log in seed.logs:
            f.write(log + "\n")
        
        

        

        f.write("\n--- Reproduction Code ---\n")
        f.write("```python\n")
        f.write("#!/usr/bin/env python3\n")
        f.write("import sys\n")
        f.write("import asyncio\n")
        f.write("from BLEClient import BLEClient\n")
        f.write("from UserInterface import ShowUserInterface\n\n")

        f.write(f"DEVICE_NAME = \"{DEVICE_NAME}\"\n")
        f.write("# Commands\n")
        f.write("AUTH = [0x00]\n")
        f.write("OPEN = [0x01]\n")
        f.write("CLOSE = [0x02]\n")
        f.write("PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]\n\n")

        # Format command sequence
        f.write("COMMAND_SEQUENCE = [\n")
        for cmd in seed.data:
            formatted_cmd = ", ".join(f"0x{b:02X}" for b in cmd)
            f.write(f"    [{formatted_cmd}],\n")
        f.write("]\n\n")

        f.write("async def control_smartlock():\n")
        f.write("    ble = BLEClient()\n")
        f.write("    ble.init_logs()\n")
        f.write("    print(f'[1] Connecting to \"{DEVICE_NAME}\"...')\n")
        f.write("    await ble.connect(DEVICE_NAME)\n\n")

        f.write("    try:\n")
        f.write("        print(\"\\n[3] Sending Commands to Smart Lock...\")\n")
        f.write("        for command in COMMAND_SEQUENCE:\n")
        f.write("            res = await ble.write_command(command)\n")
        f.write("            await asyncio.sleep(1)\n")
        f.write("    except Exception as e:\n")
        f.write("        print(f\"Exception caught: {e}\")\n")
        f.write("        await ble.disconnect()\n")
        f.write("        lines = ble.read_logs()\n")
        f.write("        for line in lines:\n")
        f.write("            print(line)\n")
        f.write("        sys.exit(0)\n\n")

        f.write("    print(\"\\n[6] Logs from Smart Lock (Serial Port):\\n\" + '-'*50)\n")
        f.write("    lines = ble.read_logs()\n")
        f.write("    for line in lines:\n")
        f.write("        print(line)\n")
        f.write("    sys.exit(0)\n\n")

        f.write("if len(sys.argv) > 1 and sys.argv[1] == \"--gui\":\n")
        f.write("    ShowUserInterface()\n")
        f.write("else:\n")
        f.write("    try:\n")
        f.write("        asyncio.run(control_smartlock())\n")
        f.write("    except KeyboardInterrupt:\n")
        f.write("        print(\"\\nProgram Exited by User!\")\n")
        f.write("```\n")

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


# ------------------------------
# Assign Energy Functions
# ------------------------------

def inverse_energy(count: int) -> float:
        """Inverse energy function: energy decreases with more executions."""
        return 1.0 / (count + 1)
    
def exponential_energy(count: int) -> float:
    """Exponential energy function: energy drops exponentially."""
    return 0.9 ** count
    
def linear_energy(count: int) -> float:
    """Linear energy function: energy drops linearly."""
    return max(0.1, 1.0 - (count * 0.1))
# ------------------------------
# Helper Functions for Mutation
# ------------------------------

def flip_random_byte(command: List[int], rng: random.Random, bitflip_range: Tuple[int, int]) -> None:
    if command:
        byte_idx = rng.randint(0, len(command) - 1)
        flip_val = rng.randint(*bitflip_range)
        command[byte_idx] ^= flip_val


def insert_random_byte(command: List[int], rng: random.Random) -> None:
    byte_idx = rng.randint(0, len(command)) if command else 0
    command.insert(byte_idx, rng.randint(0, 255))


def delete_random_byte(command: List[int], rng: random.Random) -> None:
    if len(command) > 1:
        byte_idx = rng.randint(0, len(command) - 1)
        del command[byte_idx]


def shuffle_commands(sequence: List[List[int]], rng: random.Random) -> None:
    rng.shuffle(sequence)


def duplicate_command(sequence: List[List[int]], rng: random.Random) -> None:
    cmd_idx = rng.randint(0, len(sequence) - 1)
    sequence.insert(cmd_idx, sequence[cmd_idx].copy())


def remove_random_command(sequence: List[List[int]], rng: random.Random) -> None:
    if len(sequence) > 1:
        del sequence[rng.randint(0, len(sequence) - 1)]


def truncate_commands(sequence: List[List[int]], rng: random.Random) -> None:
    for cmd in sequence:
        if len(cmd) > 1:
            cmd[:] = cmd[:rng.randint(1, len(cmd))]


def extend_last_command(sequence: List[List[int]], rng: random.Random, max_extend_bytes: int) -> None:
    if sequence:
        sequence[-1].extend([rng.randint(0, 255) for _ in range(rng.randint(1, max_extend_bytes))])


class BLEFuzzer(AFLFuzzer):

    def __init__(self, 
                 device_name: str,
                 seed_sequences: List[List[List[int]]],
                 expected_responses: List[List[int]],
                 crash_dir: str = "crashes",
                 interesting_dir: str = "interesting"):

        self.device_name = device_name
        self.expected_responses = expected_responses
        self.crash_dir = crash_dir
        self.interesting_dir = interesting_dir

        self.response_codes_seen: Set[int] = set()
        self.seen_combinations: Set[Tuple[str, str]] = set()
        self.seed_queue: List[Seed] = []
        self.failure_queue: List[Seed] = []
        self.ble_connection_count = 0
        self.logging_seed = None
        self.seed_input_count = 0
        self.mutated_seed_count = 0

        os.makedirs(self.crash_dir, exist_ok=True)
        os.makedirs(self.interesting_dir, exist_ok=True)

        self.ble = BLEClient()
        self.seed_inputs = [create_seed_from_command(seq, note=f"Seed #{i}")
                      for i, seq in enumerate(seed_sequences)]
        
        super().__init__(self.seed_inputs)

        
        print(f"Found {len(self.seed_inputs)} seed inputs.")
        for seed in self.seed_inputs:
            heapq.heappush(self.seed_queue, seed)

    async def connect_ble(self):
        print("Initializing BLE client...")
        self.ble.init_logs()
        await self.ble.connect(self.device_name)
        self.ble_connection_count += 1
        self.logging_seed = Seed(priority=1.0, energy=1.0, data=[],
                                 path_hash=str(self.ble_connection_count),
                                 mutation_note="Logging seed", logs=[])

    async def disconnect_ble(self):
        await self.ble.disconnect()

    def choose_next(self) -> Optional[Seed]:
        """Choose the next input to test based on priority."""
        if not self.seed_queue:
            return None
        seed = heapq.heappop(self.seed_queue)
        seed.execution_count += 1
        return seed

    def assign_energy(self, seed: Seed,energy_function) -> float:
        """Assign energy to a seed based on how promising it seems."""
        # Re-compute energy based on execution count
        seed.energy = energy_function(seed.execution_count)
        
        energy = seed.energy
        # Adjust energy based on path weight if available
        # if seed.path_hash in self.path_tracker.path_weights:
        #     path_weight = self.path_tracker.path_weights[seed.path_hash]
        #     energy *= path_weight
        
        # Seeds that led to crashes get extra energy
        if seed.is_error_detected:
            energy *= 3.0
        
        # Seeds with error response codes get extra energy
        if seed.response and seed.response[0] != 0:
            energy *= 1.5
        
        # Prioritize complex command sequences
        if len(seed.data) > 2:
            energy *= 1.2
            
        return energy

    def is_error(self,seed: Seed, command: List[int], actual_response: List[int], expected_responses: List[List[int]]) -> bool:
        """
        Determines if the actual BLE response indicates an error by:
        - Checking if it does not match any of the expected valid responses.
        - Checking if authentication using the DEFAULT_PASSCODE fails.
        """

        # 1. General mismatch from expected responses
        if actual_response not in expected_responses:
            return True

        # 2. Explicitly catch failed default authentication
        if command[:1] == AUTH and command[1:] == DEFAULT_PASSCODE:
            if actual_response[0] != 0:
                print("Authentication failed with the correct passcode!")
                seed.is_error_detected = True
                seed.error_code = actual_response
                print("STOPPPPP")
                return True

        return False

    def is_interesting(
            self,
        seed: Seed,
        seen_combinations: Set[Tuple[str, str]],
        response_codes_seen: Set[int],
    ) -> bool:
        """
        Determines if a seed is 'interesting' based on:
        - New input/output (path/response) combinations.
        - New/unseen response codes.
        - Long or complex sequences.
        """
        path_hash = seed.path_hash
        response_hash = seed.response_hash
        hash_pair = (path_hash, response_hash)

        

        if seed.response:
            status = seed.response[0]
            
            if status not in response_codes_seen:
                response_codes_seen.add(status)
                return True
            
        if hash_pair not in seen_combinations:
            seen_combinations.add(hash_pair)
            return True

        # if len(seed.data) > 5:
        #     return True

        return False
    
    def assign_path_weights(self,seed: Seed) -> float:
        
        """
        Assigns a custom priority to a seed based on its level of 'interestingness'.
        Lower value = higher priority in the seed queue.
        """

        # Highest priority: if it caused an error or crash
        if seed.response not in self.response_codes_seen:
            return 0.2

        # Moderate: unique non-zero response (unexpected behavior)
        # if seed.response and seed.response[0] != 0x00:
        #     return 0.3

        # Medium-low: long sequences could trigger latent state bugs
        # if len(seed.data) > 5:
        #     return 0.5

        # Default interesting priority
        return 1.0
    
        # ------------------------------
    # Main Mutation Function
    # ------------------------------

    def mutate_input(
            self,
        seed: Seed,
        mutation_weights: Optional[Dict[str, float]] = None,
        bitflip_range: Tuple[int, int] = (1, 255),
        truncation_prob: float = 0.1,
        extension_prob: float = 0.1,
        max_extend_bytes: int = 50,
        rng: Optional[random.Random] = None
    ) -> List[List[int]]:
        """
        Controlled mutation of a 2D list of BLE commands.
        """
        rng = rng or random
        command_sequence = seed.data
        mutated_sequence = [cmd.copy() for cmd in command_sequence]

        if not mutated_sequence:
            return []

        # Default mutation weights
        weights = mutation_weights or {
            'command_flip': 0.4,
            'command_insert': 0.2,
            # 'command_delete': 0.15,
            'sequence_shuffle': 0.2,
            'sequence_duplicate': 0.2,
            # 'sequence_remove': 0.15,
        }

        mutation_type = rng.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
        seed.mutation_note = mutation_type

        if mutation_type == 'command_flip':
            flip_random_byte(rng.choice(mutated_sequence), rng, bitflip_range)
        elif mutation_type == 'command_insert':
            insert_random_byte(rng.choice(mutated_sequence), rng)
        # elif mutation_type == 'command_delete':
        #     delete_random_byte(rng.choice(mutated_sequence), rng)
        elif mutation_type == 'sequence_shuffle':
            shuffle_commands(mutated_sequence, rng)
        elif mutation_type == 'sequence_duplicate':
            duplicate_command(mutated_sequence, rng)
        # elif mutation_type == 'sequence_remove':
        #     remove_random_command(mutated_sequence, rng)

        # if rng.random() < truncation_prob:
        #     truncate_commands(mutated_sequence, rng)

        if rng.random() < extension_prob:
            extend_last_command(mutated_sequence, rng, max_extend_bytes)

        return mutated_sequence

    async def fuzz(self):
        await self.connect_ble()
        print("Starting BLE Fuzzer...")

        try:
            while self.seed_queue and self.seed_input_count < NUMBER_OF_SEEDS_TESTED:
                current_seed = self.choose_next()
                if not current_seed:
                    print("No more seeds to test.")
                    break

                if self.seed_input_count == NUMBER_OF_SEEDS_TESTED:
                    print(f"{NUMBER_OF_SEEDS_TESTED} seeds have been tested.")
                    break

                self.seed_input_count += 1
                print(f"{'='*25} Seed Input {self.seed_input_count} {'='*25}")

                energy = self.assign_energy(current_seed, exponential_energy)

                
                for _ in range(max(1, int(energy * 5))):
                # for _ in range(1):  # Run mutations once for each seed

                    
                    mutated_data = self.mutate_input(current_seed)
                    flattened = [b for cmd in mutated_data for b in cmd]
                    flat_bytes = bytes(flattened)
                    path_hash = hashlib.sha256(flat_bytes).hexdigest()

                    mutated_seed = Seed(priority=1.0, energy=energy, data=mutated_data,
                                         parent_hash=current_seed.path_hash, path_hash=path_hash,
                                         mutation_note="mutation", timestamp=time.time(), logs=[])

                    self.mutated_seed_count += 1
                    print(f"Starting Mutated Seed {self.mutated_seed_count} Sequence")

                    try:
                        for command in mutated_seed.data:
                            mutated_seed.logs.append(f"Sent: {[hex(b) for b in command]}")
                            self.logging_seed.logs.append(f"Sent: {[hex(b) for b in command]}")

                            mutated_seed.number_of_commands_executed += 1
                            self.logging_seed.number_of_commands_executed += 1

                            response = await self.ble.write_command(command)
                            mutated_seed.response = bytes(response)
                            mutated_seed.response_hash = hashlib.sha256(mutated_seed.response).hexdigest()
                            mutated_seed.logs.append(f"Received: {[hex(b) for b in response]}")

                            if self.is_error(mutated_seed, command, response,self.expected_responses):
                                mutated_seed.is_error_detected = True
                                self.failure_queue.append(mutated_seed)
                                save_to("bugs", mutated_seed, lines[-1])
                                break

                        mutated_seed.is_all_commands_executed = True

                        if self.is_interesting(mutated_seed,self.seen_combinations,self.response_codes_seen):
                            mutated_seed.is_interesting = True
                            mutated_seed.logs.append("🌟 Interesting seed: new behavior or output")
                            # Assign priority based on how interesting it is
                            mutated_seed.priority = self.assign_path_weights(mutated_seed)
                            lines = self.ble.read_logs()
                            save_to("interesting", mutated_seed, lines[-1])
                            heapq.heappush(self.seed_queue, mutated_seed)

                    except Exception as e:
                        # To catch errors that crash the fuzzer
                        print(f"⚠️ Error sending command: {e}")
                        mutated_seed.logs.append(f"BLE Crashed!")
                        self.logging_seed.logs.append(f"BLE Crashed!")
                        self.logging_seed.is_error_detected = True
                        self.logging_seed.is_all_commands_executed = True
                        self.failure_queue.append(self.logging_seed)

                        lines = self.ble.read_logs()
                            

                        save_to("crashes", mutated_seed,lines[-1]) 
                        save_to("logging", self.logging_seed,lines[-1])   
                        print("Disconnecting...")
                        await self.ble.disconnect()
                        await asyncio.sleep(1)
                        print(f"[1] Connecting to '{DEVICE_NAME}'...")
                        await self.ble.connect(DEVICE_NAME)
                        await asyncio.sleep(1)
                        # Get a new logging_seed
                        self.ble_connection_count += 1
                        self.logging_seed = Seed(timestamp=time.time(), logs=[], priority=1.0, energy=1.0, data=[],path_hash=str(self.ble_connection_count), mutation_note="Logging seed")



                    

                    continue

        finally:
            await self.ble.disconnect()
            print("[!] Fuzzing session ended.")
            lines = self.ble.read_logs()

            with open("ble_logs.txt", "w", encoding="utf-8") as f:
                f.write("=== BLE LOGS ===\n\n")
                for line in lines:
                    f.write(line + "\n")

            
            print(f"Coverage Summary saved to 'test_coverage_summary.txt'")
            
            # make a file that contains all the error and analysis
                    # Save statistics to a separate test analysis coverage summary file
            with open("test_coverage_summary.txt", "w", encoding="utf-8") as summary:
                summary.write("=== BLE Fuzzer Coverage Summary ===\n")
                summary.write(f"Timestamp                  : {time.ctime()}\n")
                summary.write(f"No. of Initial Seed Inputs : {len(self.seed_inputs)}\n")
                summary.write(f"No. of seeds processed     : {self.seed_input_count}\n")
                summary.write(f"No. of mutated seeds       : {self.mutated_seed_count}\n")
                summary.write(f"BLE connections made       : {self.ble_connection_count}\n")
                summary.write(f"Unique path-response pairs : {len(self.seen_combinations)}\n")
                summary.write(f"Unique response codes      : {len(self.response_codes_seen)}\n")
                summary.write(f"Response codes seen        : {sorted(self.response_codes_seen)}\n")
                summary.write(f"Remaining seeds in queue   : {len(self.seed_queue)}\n")
                summary.write(f"Failure queue size         : {len(self.failure_queue)}\n")

            # Save failure seeds individually into "failureQueue/" folder
            os.makedirs("failureQueue", exist_ok=True)
            for i, failed_seed in enumerate(self.failure_queue):
                file_name = f"failure_{i+1}_{failed_seed.path_hash[:8]}.txt"
                file_path = os.path.join("failureQueue", file_name)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("=== Failed Seed ===\n")
                    f.write(f"Timestamp       : {time.ctime(failed_seed.timestamp)}\n")
                    f.write(f"Path Hash       : {failed_seed.path_hash}\n")
                    f.write(f"Parent Hash     : {failed_seed.parent_hash}\n")
                    f.write(f"Error Detected  : {failed_seed.is_error_detected}\n")
                    f.write(f"Error Code      : {failed_seed.error_code}\n")
                    f.write(f"Priority        : {failed_seed.priority:.4f}\n")
                    f.write(f"Energy          : {failed_seed.energy:.4f}\n")
                    f.write(f"Mutation Note   : {failed_seed.mutation_note}\n")
                    f.write(f"Commands Sent   :\n")
                    for cmd in failed_seed.data:
                        f.write(f"  {[f'0x{b:02X}' for b in cmd]}\n")
                    f.write(f"\nLogs:\n")
                    for log in failed_seed.logs:
                        f.write(f"{log}\n")

                    f.write("\n--- Reproduction Code ---\n")
                    f.write("```python\n")
                    f.write("#!/usr/bin/env python3\n")
                    f.write("import sys\n")
                    f.write("import asyncio\n")
                    f.write("from BLEClient import BLEClient\n")
                    f.write("from UserInterface import ShowUserInterface\n\n")

                    f.write(f"DEVICE_NAME = \"{DEVICE_NAME}\"\n")
                    f.write("# Commands\n")
                    f.write("AUTH = [0x00]\n")
                    f.write("OPEN = [0x01]\n")
                    f.write("CLOSE = [0x02]\n")
                    f.write("PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]\n\n")

                    # Format command sequence
                    f.write("COMMAND_SEQUENCE = [\n")
                    for cmd in failed_seed.data:
                        formatted_cmd = ", ".join(f"0x{b:02X}" for b in cmd)
                        f.write(f"    [{formatted_cmd}],\n")
                    f.write("]\n\n")

                    f.write("async def control_smartlock():\n")
                    f.write("    ble = BLEClient()\n")
                    f.write("    ble.init_logs()\n")
                    f.write("    print(f'[1] Connecting to \"{DEVICE_NAME}\"...')\n")
                    f.write("    await ble.connect(DEVICE_NAME)\n\n")

                    f.write("    try:\n")
                    f.write("        print(\"\\n[3] Sending Commands to Smart Lock...\")\n")
                    f.write("        for command in COMMAND_SEQUENCE:\n")
                    f.write("            res = await ble.write_command(command)\n")
                    f.write("            await asyncio.sleep(1)\n")
                    f.write("    except Exception as e:\n")
                    f.write("        print(f\"Exception caught: {e}\")\n")
                    f.write("        await ble.disconnect()\n")
                    f.write("        lines = ble.read_logs()\n")
                    f.write("        for line in lines:\n")
                    f.write("            print(line)\n")
                    f.write("        sys.exit(0)\n\n")

                    f.write("    print(\"\\n[6] Logs from Smart Lock (Serial Port):\\n\" + '-'*50)\n")
                    f.write("    lines = ble.read_logs()\n")
                    f.write("    for line in lines:\n")
                    f.write("        print(line)\n")
                    f.write("    sys.exit(0)\n\n")

                    f.write("if len(sys.argv) > 1 and sys.argv[1] == \"--gui\":\n")
                    f.write("    ShowUserInterface()\n")
                    f.write("else:\n")
                    f.write("    try:\n")
                    f.write("        asyncio.run(control_smartlock())\n")
                    f.write("    except KeyboardInterrupt:\n")
                    f.write("        print(\"\\nProgram Exited by User!\")\n")
                    f.write("```\n")

        sys.exit(0)

# === Async Entry Point ===
async def main():
    fuzzer = BLEFuzzer(
        device_name=DEVICE_NAME,
        seed_sequences=SEED_COMMAND_SEQUENCES,
        expected_responses=EXPECTED_RESPONSES,
        crash_dir=CRASH_DIR,
        interesting_dir=INTERESTING_DIR
    )
    await fuzzer.fuzz()

# === Run ===
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Fuzzing manually interrupted.")