# main_ble_fuzzer.py

import asyncio
import random
import hashlib
import heapq
import os
from BLEClient import BLEClient
from ble_mutator import mutate_command
from ble_oracle import is_crash, is_interesting

DEVICE_NAME = "Smart Lock [Group 7]"

# AFL-style priority queue
queue = []
seen_paths = {}
crash_dir = "crashes"
interesting_dir = "interesting"
os.makedirs(crash_dir, exist_ok=True)
os.makedirs(interesting_dir, exist_ok=True)

def get_path_id(response, logs):
    """Generate a unique path ID using response and serial logs."""
    combined = str(response) + "".join(logs[-5:])  # last 5 logs
    return hashlib.md5(combined.encode()).hexdigest()

def assign_energy():
    """Assign fuzzing energy to each test case."""
    return random.expovariate(0.5)

def save_to(folder, cmd):
    with open(f"{folder}/case_{random.randint(1000,9999)}.bin", "wb") as f:
        f.write(cmd)

async def fuzz_loop():
    ble = BLEClient()
    ble.init_logs()
    await ble.connect(DEVICE_NAME)

    # Initial seed (AUTH + valid passcode)
    seed_cmd = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    heapq.heappush(queue, (-1.0, seed_cmd))

    try:
        while queue:
            _, cmd = heapq.heappop(queue)
            energy = assign_energy()

            for _ in range(int(energy * 5)):
                mutated = mutate_command(cmd)
                response = await ble.write_command(mutated)
                logs = ble.read_logs()
                path_id = get_path_id(response, logs)

                if is_crash(logs):
                    save_to(crash_dir, mutated)
                    print("🔥 Crash detected and saved.")
                elif is_interesting(response, seen_paths):
                    save_to(interesting_dir, mutated)
                    print("🤔 Interesting case detected and saved.")

                seen_paths[path_id] = True
                heapq.heappush(queue, (-random.random(), mutated))

    except Exception as e:
        print(f"⚠️ Fuzzer error: {e}")
    finally:
        await ble.disconnect()

if __name__ == "__main__":
    asyncio.run(fuzz_loop())
