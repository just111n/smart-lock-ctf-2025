import sys
import asyncio
import hashlib
import time
from typing import List

from fuzzer_class import Fuzzer
from BLEClient import BLEClient
from utils import Seed


# ========================= BLE DEVICE CONFIG ========================
DEVICE_NAME = "Smart Lock [Group 7]"

# ========================== COMMAND SETUP ==========================



AUTH:List[int] = [0x00]
OPEN:List[int] = [0x01]
CLOSE:List[int] = [0x02]
DEFAULT_PASSCODE:List[int] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]

EXPECTED_RESPONSES:List[List[int]] = [[0x00], [0x01], [0x02], [0x03], [0x04]]

SEED_COMMAND_SEQUENCES = [
    [[0xAA, 0xAA]],                           # Special
    [[0x00]], [[0x03]], [[0xFF]],             # Invalid/Unknown
    [AUTH + DEFAULT_PASSCODE[:3]],            # Incomplete AUTH
    [AUTH + DEFAULT_PASSCODE], [CLOSE],       # Locking
    [AUTH + DEFAULT_PASSCODE, OPEN],
    [AUTH + DEFAULT_PASSCODE, CLOSE],
    [AUTH + DEFAULT_PASSCODE, OPEN, OPEN],
    [OPEN], [CLOSE],                          # Basic commands
    [OPEN, CLOSE], [CLOSE, OPEN],
    [OPEN, OPEN], [CLOSE, CLOSE],
    [AUTH + DEFAULT_PASSCODE, OPEN, CLOSE],
    [AUTH + DEFAULT_PASSCODE, CLOSE, OPEN],
    [AUTH + DEFAULT_PASSCODE, AUTH + DEFAULT_PASSCODE],
    [AUTH + DEFAULT_PASSCODE, OPEN, CLOSE, OPEN, CLOSE],
    [[0x00]], [[0x03]], [[0xFF]],             # Repeat edge cases
    [AUTH + DEFAULT_PASSCODE[:3]]
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
        logs = self.client.read_logs()

        with open("ble_client_logs.txt", "w", encoding="utf-8") as f:
            f.write("=== BLE Client Logs ===\n\n")
            for line in logs:
                f.write(line + "\n")

        return logs

    def get_seed_inputs(self, raw_sequences: List[List[List[int]]]) -> List[Seed]:
        return [create_seed_from_command(seq, f"Predefined #{i}") for i, seq in enumerate(raw_sequences)]
    
    ## add method to save error seeds or modify how error seeds are being saved for
    #  reproduction of error from error seeds


    ## add method to save interesting seeds??

# ========================== FUZZING EXECUTION ==========================

async def main():
    target = BLETarget(DEVICE_NAME)

    fuzzer = Fuzzer(
        target=target,
        raw_seed_sequences=SEED_COMMAND_SEQUENCES,
        expected_responses=EXPECTED_RESPONSES,
        target_name=DEVICE_NAME,
        crash_dir="ble_crashes",
        interesting_dir="ble_interesting"
    )

    await fuzzer.run()
    sys.exit(0)

# ========================== ENTRY POINT ==========================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Terminated by user.")
