#!/usr/bin/env python3
import sys
import asyncio
from BLEClient import BLEClient
from UserInterface import ShowUserInterface
from typing import List, Dict, Set, Tuple, Any, Optional
from utils import Seed

DEVICE_NAME = "Smart Lock [Group 7]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
DEFAULT_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE

COMMAND_SEQUENCE = [
    1,
    [0,1,2,3,4,5,6]
    ]

def is_error(seed: Seed, command: List[int], actual_response: List[int], expected_responses: List[List[int]]) -> bool:
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
        print("first conditonal is true")
        if actual_response[0] != 0:
            print("Authentication failed with the correct passcode!")
            # seed.is_error_detected = True
            # seed.error_code = actual_response
            return True

    return False

async def example_control_smartlock():
    # Use this code as template to create your fuzzer
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    # print("\n[2] Authenticating...")
    # res = await ble.write_command(AUTH + PASSCODE)
    # if res[0] != 0:
    #     print(f"[X] Failure: Wrong Passcode.")
    #     await ble.disconnect()
    #     return

    # print("[!] Authenticated!!!")
    # await asyncio.sleep(2)

    
    # ====== commands to test ===========

    # trigger authentication falure
    await ble.write_command([191])
    await asyncio.sleep(2)

    # open commands trigger error code to be shown in logs
    await ble.write_command([0])
    await asyncio.sleep(2)
    
    # auth fails here
    await ble.write_command([0, 1, 2, 3, 4, 5, 6])
    await asyncio.sleep(2)

    

    # TODO: How do I deal with this authentication failure?
    # I need to clear it by disconnecting or restting it somehow

    print("\n[5] Disconnecting...")
    await ble.disconnect()

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    await ble.write_command([0xAA, 0xAA])
    await asyncio.sleep(2)
    # await ble.write_command([0])
    # await asyncio.sleep(2)
 
    
    

    # print("\n[5] Disconnecting...")
    # await ble.disconnect()


    # ======= Print logs =======
    print(f"\n[6] Logs from Smart Lock (Serial Port):\n{'-'*50}")
    lines = ble.read_logs()  # Return a list of all log lines.
    for line in lines:
        print(line)
    # TIP: Use lines[-1] to get the most recent line

    sys.exit(0)


        
        


    


# Show User interface if command line contains --gui
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    # Ortherwise, run this example
    try:
        asyncio.run(example_control_smartlock())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
