import asyncio
import threading
import time
import hashlib
from typing import List

from fuzzer_class import Fuzzer
from BLEClient import BLEClient
from utils import Seed

DEVICE_NAME = "Smart Lock [Group 7]"
AUTH = [0x00]
OPEN = [0x01]
CLOSE = [0x02]
DEFAULT_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
EXPECTED_RESPONSES = [[0x00], [0x01], [0x02], [0x03], [0x04]]

SEED_COMMAND_SEQUENCES = [
    [AUTH + DEFAULT_PASSCODE],
    [[0xAA, 0xAA]],
    [[0x00]], [[0xFF]],
    [AUTH + DEFAULT_PASSCODE, OPEN],
    [AUTH + DEFAULT_PASSCODE, CLOSE],
    [AUTH + DEFAULT_PASSCODE, OPEN, CLOSE]
]

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
        logs=[f"Seed from thread at {time.ctime()}"]
    )

class BLETarget:
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
            await asyncio.sleep(0.05)
            response = res
        return response

    def get_logs(self) -> str:
        logs = self.client.read_logs()
        with open(f"ble_logs_{threading.get_ident()}.txt", "w", encoding="utf-8") as f:
            for line in logs:
                f.write(line + "\n")
        return logs

    def get_seed_inputs(self, raw_sequences: List[List[List[int]]]) -> List[Seed]:
        return [create_seed_from_command(seq, f"Thread Seed #{i}") for i, seq in enumerate(raw_sequences)]

# --------------------------
# Thread-Local Async Runner
# --------------------------

def run_fuzzer_in_thread(thread_id: int):
    async def fuzz_runner():
        target = BLETarget(DEVICE_NAME)
        fuzzer = Fuzzer(
            target=target,
            raw_seed_sequences=SEED_COMMAND_SEQUENCES,
            expected_responses=EXPECTED_RESPONSES,
            target_name=f"{DEVICE_NAME}_Thread_{thread_id}",
            crash_dir=f"ble_crashes_t{thread_id}",
            interesting_dir=f"ble_interesting_t{thread_id}"
        )
        await fuzzer.run()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(fuzz_runner())
    finally:
        loop.close()

# --------------------------
# Launch Both Fuzzers
# --------------------------

if __name__ == "__main__":
    print("🚀 Launching 2 concurrent fuzzers on the same BLE target...\n")
    
    t1 = threading.Thread(target=run_fuzzer_in_thread, args=(1,))
    t2 = threading.Thread(target=run_fuzzer_in_thread, args=(2,))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print("\n✅ Both fuzzers finished. Check logs and output directories.")
