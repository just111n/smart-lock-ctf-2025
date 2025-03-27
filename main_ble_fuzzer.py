# STEP 2: Enhanced Fuzzer - Support for unauthenticated + authenticated fuzzing

import logging
import asyncio
import random
import hashlib
import heapq
import os
import sys
from BLEClient import BLEClient
from ble_mutator import mutate_command
from ble_oracle import is_crash, is_interesting
from UserInterface import ShowUserInterface
from utils import generate_invalid_commands

DEVICE_NAME = "Smart Lock [Group 7]"

# Commands
AUTH = [0x00]
OPEN = [0x01]
CLOSE = [0x02]
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Valid passcode

queue = []
seen_paths = {}
crash_dir = "crashes"
interesting_dir = "interesting"
os.makedirs(crash_dir, exist_ok=True)
os.makedirs(interesting_dir, exist_ok=True)

def get_path_id(response, logs):
    combined = str(response) + "".join(logs[-5:])
    return hashlib.md5(combined.encode()).hexdigest()

def assign_energy():
    return random.expovariate(0.5)

def save_to(folder, cmd, as_text=False):
    cmd_copy = bytearray(cmd)
    hex_part = "_".join(f"{byte:02X}" for byte in cmd_copy[:8])
    filename = f"case_{hex_part}_{random.randint(1000, 9999)}"
    path = f"{folder}/{filename}.txt" if as_text else f"{folder}/{filename}.bin"
    with open(path, "w" if as_text else "wb") as f:
        if as_text:
            hex_list = [f"0x{byte:02X}" for byte in cmd_copy]
            f.write(f"[{', '.join(hex_list)}]\n")
        else:
            f.write(cmd_copy)

async def fuzz_once(ble, cmd):
    try:
        response = await ble.write_command(bytes(cmd))
        await asyncio.sleep(1.5)
        logs = ble.read_logs()
        path_id = get_path_id(response, logs)

        if is_crash(logs):
            save_to(crash_dir, cmd, as_text=True)
            print("🔥 Crash detected and saved.")
        elif is_interesting(response, seen_paths):
            save_to(interesting_dir, cmd, as_text=True)
            print("🤔 Interesting case saved.")

        seen_paths[path_id] = True
        return True
    except Exception as e:
        print(f"⚠️ BLE command error: {e}.")
        return False

async def fuzz_loop():
    ble = BLEClient()
    ble.init_logs()
    print(f"[1] Connecting to '{DEVICE_NAME}'...")
    await ble.connect(DEVICE_NAME)

    print("[2] Seeding commands (unauthenticated + authenticated)...")
    # AUTH seeds to test login fuzzing
    auth_variants = [AUTH + PASSCODE] + generate_invalid_commands()
    for auth_cmd in auth_variants:
        heapq.heappush(queue, (-1.0, bytearray(auth_cmd)))

    # Valid post-auth commands to fuzz (OPEN, CLOSE, etc.)
    post_auth_seeds = [
        bytearray(OPEN),
        bytearray(CLOSE),
        bytearray([0x03]),  # unknown command
    ]
    for seed in post_auth_seeds:
        heapq.heappush(queue, (-1.0, seed))

    try:
        while queue:
            _, cmd = heapq.heappop(queue)
            energy = assign_energy()

            for _ in range(max(1, int(energy * 5))):
                mutated = mutate_command(cmd[:])

                # Reset and reconnect for every run to simulate cold start
                await ble.disconnect()
                await asyncio.sleep(1)
                await ble.connect(DEVICE_NAME)
                await asyncio.sleep(1)

                print(f"\n[>] Testing: {[hex(b) for b in mutated]}")
                await fuzz_once(ble, mutated)

                heapq.heappush(queue, (-random.random(), mutated))

    except Exception as e:
        print(f"⚠️ Fuzzer error: {e}")
    finally:
        await ble.disconnect()
        print("[!] Fuzzing session ended.")
        lines = ble.read_logs()
        for line in lines:
            print(line)
        sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    try:
        asyncio.run(fuzz_loop())
        ShowUserInterface()

    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
