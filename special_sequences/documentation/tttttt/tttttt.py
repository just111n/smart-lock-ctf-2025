from BLEClient import BLEClient

import asyncio
async def main():
    ble = BLEClient()
    ble.init_logs()
    await ble.connect("Smart Lock [Group 7]")
    await ble.write_command([255, 255, 255, 255])
    await asyncio.sleep(2)
    await ble.write_command([255, 255, 255, 255])
    await asyncio.sleep(2)
    await ble.write_command([255, 255, 255, 255])
    await asyncio.sleep(2)
    await ble.write_command([255, 255, 255, 255])
    await asyncio.sleep(2)

    logs = ble.read_logs()
    for log in logs:
        print(log)

asyncio.run(main())
