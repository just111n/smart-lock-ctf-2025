#!/usr/bin/env python3
import asyncio
import sys
from BLEClient import BLEClient

# Define BLE Smart Lock Device Name
DEVICE_NAME = "Smart Lock [Group 7]"
AUTH = [0x00]  # Authentication command

# File paths for input and output logs
INPUT_FILE = "input_cases.txt"
OUTPUT_FILE = "output_results.txt"
FEEDBACK_FILE = "feedback_data.txt"


async def fuzz_from_file():
    """ Reads input test cases from file and tests them on the smart lock """
    ble = BLEClient()
    await ble.connect(DEVICE_NAME)

    # Read fuzz test cases from file
    with open(INPUT_FILE, "r") as f:
        test_cases = [list(map(int, line.strip().split(","))) for line in f.readlines()]

    feedback_data = []

    for i, passcode in enumerate(test_cases):
        print(f"\n[!] Testing Passcode {i+1}: {passcode}")

        try:
            res = await ble.write_command(AUTH + passcode)
            logs = ble.read_logs()

            # Categorize response
            if not res or res == [0xFF, 0xFF]:
                print("[X] Crash detected!")
                feedback_data.append((passcode, "Crash"))
            elif logs and any("error" in log.lower() for log in logs):
                print("[X] Error Log detected!")
                feedback_data.append((passcode, "Error Log"))
            else:
                feedback_data.append((passcode, "Normal"))

        except Exception as e:
            print(f"[X] Exception occurred: {e}")
            feedback_data.append((passcode, "Exception"))

    # Store feedback for future analysis
    with open(FEEDBACK_FILE, "a") as f:
        for case, status in feedback_data:
            f.write(",".join(map(str, case)) + f", Status: {status}\n")

    # Store test cases that caused crashes/errors for retesting
    with open(OUTPUT_FILE, "a") as f:
        for case, status in feedback_data:
            if status in ["Crash", "Error Log", "Exception"]:
                f.write(",".join(map(str, case)) + f", Reason: {status}\n")

    print("\n[!] Disconnecting...")
    await ble.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(fuzz_from_file())
    except KeyboardInterrupt:
        print("\n[!] Program Exited by User!")
