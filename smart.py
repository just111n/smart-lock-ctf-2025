#!/usr/bin/env python3
import sys
import asyncio
import random
import logging
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

# Configure logging
logging.basicConfig(
    filename="fuzzer_errors.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DEVICE_NAME = "Smart Lock [Group 7]"  # Modify here to match your group

# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte

# Correct Passcode
VALID_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]

# Generate random invalid commands
def generate_invalid_commands():
    return [
        [random.randint(0, 255)],  # Single random byte
        [random.randint(0, 255) for _ in range(2)],  # Two random bytes
        [random.randint(0, 255) for _ in range(3)],  # Three bytes
        [random.randint(0, 255) for _ in range(10)],  # Oversized command
        [OPEN],
        [OPEN + [CLOSE]]  # Fixed: Correctly appending CLOSE
    ]

# Append the last error log to fuzzer_errors.log on startup
def append_last_error_log():
    try:
        with open("fuzzer_errors.log", "r") as log_file:
            lines = log_file.readlines()
            last_log = lines[-1] if lines else "No previous logs"
    except FileNotFoundError:
        last_log = "No previous logs"
    
    with open("fuzzer_errors.log", "a") as log_file:
        log_file.write("\n[STARTUP] Last Log: " + last_log + "\n")

append_last_error_log()  # Run this on startup

# Function to send a sequence of commands (including combinations)
async def send_commands(ble, command_sequence):
    for idx, cmd in enumerate(command_sequence):
        print(f"Sending command {idx + 1}: {cmd}")
        res = await ble.write_command(cmd)
        print(f"Response: {res}")
        await asyncio.sleep(1)

async def fuzz_smartlock():
    try:
        ble = BLEClient()
        ble.close_serialport()
        ble.init_logs()  # Enable serial logging


        print(f'[1] Connecting to "{DEVICE_NAME}"...')
        await ble.connect(DEVICE_NAME)

        print("\n[2] Authenticating...")
        res = await ble.write_command(AUTH + VALID_PASSCODE)
        if res and res[0] != 0:
            print("[X] Failure: Wrong Passcode.")
            await ble.disconnect()
            return
        
        print("[!] Authenticated!!!")
        await asyncio.sleep(2)

        # Define a command sequence
        command_sequence = [
            AUTH + VALID_PASSCODE,  # Authentication command
            CLOSE,
            OPEN,                    # Open command
            CLOSE,                   # Close command
            OPEN + AUTH + CLOSE

           # OPEN + CLOSE             # Combination of Open and Close commands
        ]
        #print("\n[3] Sending different combinations of initial commands...")
        #await send_commands(ble, command_sequence)
        print("\n[3] trying infite loop...")
        for i in range(10):
            # res = await ble.write_command(VALID_PASSCODE + AUTH)
            # res = await ble.write_command(OPEN + AUTH)
            # res = await ble.write_command(CLOSE+ AUTH)
            # res = await ble.write_command(CLOSE)
            # res = await ble.write_command(OPEN)

            # res = await ble.write_command(AUTH + CLOSE)

            # res = await ble.write_command(AUTH + OPEN)
            res = await ble.write_command(OPEN)
            res = await ble.write_command(AUTH )

            for i in range(10):
                res = await ble.write_command(CLOSE)
                res = await ble.write_command(OPEN)
            

            
            

            

            


        # Get the most recent log entry and append it to fuzzer_errors.log
        print(f"\n[4] Logs from Smart Lock (Serial Port):\n{'-'*50}")

        print("\n[5] Retrieving Serial Logs...")
        logs = ble.read_logs()
        for line in logs:
            print(line)
        last_log = logs[-1] if logs else "No logs found"
        logging.error(f"Last Log: {last_log}")
        logging.getLogger().handlers[0].flush()  # Force log flush

        print("\n[6] Disconnecting...")
        await ble.disconnect()
    
    except Exception as e:
        logging.error("Fuzzer crashed with error: %s", str(e), exc_info=True)
        logging.getLogger().handlers[0].flush()  # Force log flush
        print("\n[!] An error occurred! Check fuzzer_errors.log for details.")

# Show User Interface if command line contains --gui
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    try:
        asyncio.run(fuzz_smartlock())  # Run the fuzzer
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
    except Exception as e:
        logging.error("Unhandled error: %s", str(e), exc_info=True)
        logging.getLogger().handlers[0].flush()  # Force log flush
        print("\n[!] Fatal error! Check fuzzer_errors.log.")
