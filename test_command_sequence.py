#!/usr/bin/env python3
import sys
import asyncio
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

DEVICE_NAME = "Smart Lock [Group 7]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE

COMMAND_SEQUENCE = [

     [ 0xAA,0xAA , 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0x04, 0x05, 0x06],[0x00, 0xAF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x6B, 0x37],[0xFF, 0x01, 0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0xC8, 0x06],[0x00, 0x01, 0x08, 0x73],[0xFF, 0x01, 0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x06],[0x00, 0x01, 0x08, 0x73, 0xC4, 0x4E],[0xFF, 0x01, 0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x4D, 0x01, 0x08, 0x73],[0x00, 0x01, 0x08, 0x73, 0xC4, 0x4E],[0xFF],[0x00, 0x01, 0x02, 0x03, 0x04, 0x06],[0x01, 0x02],
    #  [0x00, 0x01, 0x02, 0x03, 0x04, 0x06],
    ]




async def example_control_smartlock():
    # Use this code as template to create your fuzzer
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    try: 
        print("\n[3] Sending Commands to Smart Lock...")

        for command in COMMAND_SEQUENCE:
            res = await ble.write_command(command)
            await asyncio.sleep(1)

        

        

    except Exception as e:
        print(f"Execption caught: {e}")
        print("Disconnecting...")
        await ble.disconnect()

    
    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    try: 
        print("\n[3] Sending Commands to Smart Lock...")

        for command in COMMAND_SEQUENCE:
            res = await ble.write_command(command)
            await asyncio.sleep(1)

        

        print(f"\n[6] Logs from Smart Lock (Serial Port):\n{'-'*50}")
        lines = ble.read_logs()  # Return a list of all log lines.
        for line in lines:
            print(line)
        # TIP: Use lines[-1] to get the most recent line
        sys.exit(0)

    except Exception as e:
        print(f"Execption caught: {e}")
        print("Disconnecting...")
        await ble.disconnect()


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
