# mock_ble_interface.py

import asyncio
import random

class BLEClient:

    def __init__(self):
        self.command_history = []
        self.serialport_logs = []

    async def connect(self, device_name):
        print(f"[SIMULATED] Connected to virtual device: {device_name}")
        return True

    async def disconnect(self):
        print("[SIMULATED] Disconnected.")
        return True

    async def write_command(self, command_data):
        print(f"[SIMULATED] Sent command: {command_data}")
        self.command_history.append(command_data)
        
        # Fake response logic
        if command_data[:1] == bytes([0x00]):  # AUTH
            if command_data[1:] == bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]):
                res = [0x01]  # Auth success
                self.serialport_logs.append("Auth success")
            else:
                res = [0xFF]  # Auth fail
                self.serialport_logs.append("Auth failed")
        elif command_data[:1] == bytes([0x01]):
            res = [0xAA]  # Open response
            self.serialport_logs.append("Lock opened")
        elif command_data[:1] == bytes([0x02]):
            res = [0xBB]  # Close response
            self.serialport_logs.append("Lock closed")
        else:
            res = [0x00]
            self.serialport_logs.append("Unknown command")

        await asyncio.sleep(0.1)
        return res

    async def read_command(self):
        return [random.randint(0, 255)]

    def init_logs(self):
        self.serialport_logs = []

    def read_logs(self):
        return self.serialport_logs[-5:]
