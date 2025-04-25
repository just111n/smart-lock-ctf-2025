import sys
import asyncio
import hashlib
import time
from typing import List,Optional, Dict, Tuple

from fuzzer_class import Fuzzer
from BLEClient import BLEClient
from utils import Seed

import random


# ========================= BLE DEVICE CONFIG ========================
DEVICE_NAME = "Smart Lock [Group 7]"

# ========================== COMMAND SETUP ==========================



AUTH:List[int] = [0x00]
OPEN:List[int] = [0x01]
CLOSE:List[int] = [0x02]
DEFAULT_PASSCODE:List[int] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
WRONG_PASSCODE:List[int] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07]

EXPECTED_RESPONSES:List[List[int]] = [[0x00], [0x01], [0x02], [0x03], [0x04]]

SEED_COMMAND_SEQUENCES:List[List[List[int]]] = [
    [AUTH + WRONG_PASSCODE,OPEN], # Auth + Open + Close
     
     [[0xAA,0xAA],OPEN],
    [AUTH + DEFAULT_PASSCODE],
     [AUTH+DEFAULT_PASSCODE+[0xF1]],
     [[0x3F,0x3F,0x3F]],
     [[0xFF]*4],


    # SPECIAL
    [AUTH+DEFAULT_PASSCODE],
     
       
    [[0x01]*255],
    [[0x02]*255],
    [[0x03]*255],
    [[0x3F]*255],
    # [[0x3F]+DEFAULT_PASSCODE]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x01],[0x0A],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],],
    [AUTH + DEFAULT_PASSCODE,OPEN,[0x0A],CLOSE],
    [OPEN , CLOSE],            # Open then Close
    # Command sequences in a single frame
    [OPEN , CLOSE],            # Open then Close
    [CLOSE , OPEN],            # Close then Open
    [OPEN , OPEN],             # Open twice
    [CLOSE , CLOSE],           # Close twice
    [[0x0A],[0xFF]*4],
    
    
    
    
    # Complex state transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE], # Auth + Open + Close
    [AUTH + DEFAULT_PASSCODE , CLOSE , OPEN], # Auth + Close + Open
    
    # Double authentication scenarios (potential bugs)
    [AUTH + DEFAULT_PASSCODE , AUTH + DEFAULT_PASSCODE],
    
    # Full sequences
    [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE , OPEN , CLOSE],
    # Basic protocol tests
    [AUTH + DEFAULT_PASSCODE],  # Valid authentication
    [OPEN],                     # Open command
    [CLOSE],                    # Close command
    
    # State transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN],  # Auth + Open
    [AUTH + DEFAULT_PASSCODE , CLOSE], # Auth + Close
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]],
    
    
    # Basic protocol tests
    [AUTH + DEFAULT_PASSCODE],  # Valid authentication
    [OPEN],                     # Open command
    [CLOSE],                    # Close command
    
    # State transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN],  # Auth + Open
    [AUTH + DEFAULT_PASSCODE , CLOSE], # Auth + Close
    
    
    
    # Edge cases exploration
    [[0x00]],  # AUTH without passcode
    [[0x03]],  # Unknown command (off-by-one from CLOSE)
    [[0xFF]],  # Invalid command (maximum value)
    
    [AUTH + DEFAULT_PASSCODE[:3]],  # AUTH with incomplete passcode

    [[0x3F]],
    [[0xAA]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]],
    [AUTH + WRONG_PASSCODE , OPEN],  # Auth + Open
    [AUTH + WRONG_PASSCODE , CLOSE], # Auth + Close
    [[0xFF]*4],  # Invalid command (maximum value)
    [[0xAA,0xAA]],
    
    [AUTH + DEFAULT_PASSCODE , OPEN+CLOSE],  # Auth + Open
    [[0x04],[0x04],[0x04],[0x04],[0x04]],
    [[0x0B]],
]

# ========================== SEED CONVERSION HELPER ==========================

def create_seed_from_command(data: List[List[int]], note: str = "") -> Seed:
    flattened = [byte for cmd in data for byte in cmd]
    flat_bytes = bytes(flattened)
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

# ========================== BLE TARGET ADAPTER ==========================

class BLETarget:
    """Adapter to allow BLEClient to be used as a fuzzing target."""

    def __init__(self, device_name: str):
        self.device_name = device_name
        self.client = BLEClient()

    async def setup(self):
        await self.client.connect(self.device_name)
        self.client.init_logs()

    async def teardown(self):
        await self.client.disconnect()

    async def send_input(self, command_sequence: List[List[int]]) -> List[int]:
        response = []
        for command in command_sequence:
            res = await self.client.write_command(command)
            await asyncio.sleep(1)  # Allow BLE stack/device to respond
            response = res
        return response

    def get_logs(self) -> str:
        """Retrieve logs from the BLE client."""

        # ======= BLE Client Logs =======
        logs = self.client.read_logs()


        # ======= Save Logs to File =======
        with open("ble_client_logs.txt", "w", encoding="utf-8") as f:
            f.write("=== BLE Client Logs ===\n\n")
            for line in logs:
                f.write(line + "\n")

        return logs

    def get_seed_inputs(self, raw_sequences: List[List[List[int]]]) -> List[Seed]:
        return [create_seed_from_command(seq, f"Predefined #{i}") for i, seq in enumerate(raw_sequences)]
    

        # ------------------------------
    # Main Mutation Function
    # ------------------------------

    def mutate_input(self,
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
            'command_flip': 0.3,
            'command_insert': 0.15,
            # 'command_delete': 0.15,
            'sequence_shuffle': 0.1,
            'sequence_duplicate': 0.15,
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
    
    ## add method to save error seeds or modify how error seeds are being saved for
    #  reproduction of error from error seeds


    ## add method to save interesting seeds??

# ========================== FUZZING EXECUTION ==========================

async def main():
    target = BLETarget(DEVICE_NAME)

    fuzzer1 = Fuzzer(
        target=target,
        raw_seed_sequences=SEED_COMMAND_SEQUENCES,
        expected_responses=EXPECTED_RESPONSES,
        target_name=DEVICE_NAME,
        crash_dir="ble_crashes",
        interesting_dir="ble_interesting"
    )

    

    await fuzzer1.run(),
       
    sys.exit(0)

# ========================== ENTRY POINT ==========================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Terminated by user.")
