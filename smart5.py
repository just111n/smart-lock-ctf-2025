#!/usr/bin/env python3
import sys
import asyncio
import csv
import logging
import signal
from BLEClient import BLEClient

# Configure logging
logging.basicConfig(
    filename="fuzzer_errors.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class StateMachineFuzzer:
    def __init__(self, ble_client, device_name):
        self.ble = ble_client
        self.device_name = device_name
        self.results_file = "state_machine_results.csv"
        self.prev_sequence = []  # Track previous sequence

        self.command_map = {
            "AUTH": [0x00],
            "VALIDPASSCODE": [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            "OPEN": [0x01],
            "CLOSE": [0x02]
        }

        with open(self.results_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Commands', 'Last Logs', 'Error'])

    def calculate_log_limit(self):
        """Determine how many logs to capture based on previous sequence."""
        if not self.prev_sequence:
            return 5  # Default for the first sequence
        return 5 + 2 * len(self.prev_sequence)

    def get_last_logs(self):
        """Retrieve the latest logs up to the computed limit."""
        logs = self.ble.read_logs()
        log_limit = self.calculate_log_limit()
        return logs[-log_limit:] if logs else ["No logs found"]

    async def power_drop_and_reconnect(self):
        """Simulate power drop and reconnection."""
        print("\n--- Simulating Signal Drop ---")

        try:
            await self.ble.disconnect()
        except Exception as disconnect_error:
            logging.error(f"Disconnection Error during Signal Drop: {disconnect_error}")

        await asyncio.sleep(2)  # Simulate device power loss

        print("--- Powering Up and Reconnecting ---")
        try:
            await self.ble.connect(self.device_name)
        except Exception as connect_error:
            logging.error(f"Reconnection Error: {connect_error}")
            return False

        return True

    async def run_state_machine(self, test_commands):
        reconnect_success = await self.power_drop_and_reconnect()
        if not reconnect_success:
            self.log_results(test_commands, ["No logs"], "Signal Drop Reconnection Failed")
            return

        last_logs = self.get_last_logs()
        error = "No error"

        try:
            # Authenticate
            try:
                auth_cmd = self.command_map["AUTH"] + self.command_map["VALIDPASSCODE"]
                await self.ble.write_command(auth_cmd)
            except Exception as auth_error:
                error = f"Authentication Error: {auth_error}"
                self.log_results(test_commands, last_logs, error)
                return

            # Execute test commands
            final_response = None
            try:
                for cmd in test_commands:
                    final_response = await self.ble.write_command(self.command_map[cmd])
            except Exception as cmd_error:
                error = f"Command Error: {cmd_error}"

            # Close lock if needed
            try:
                if final_response != [0x04] and test_commands[-1] != "CLOSE":
                    await self.ble.write_command(self.command_map["CLOSE"])
            except Exception as close_error:
                error = f"Close Error: {close_error}"

            self.log_results(test_commands, last_logs, error)

        except Exception as unexpected_error:
            error = f"Unexpected Error: {unexpected_error}"
            self.log_results(test_commands, last_logs, error)

        finally:
            self.prev_sequence = test_commands  # Update last sequence
            try:
                await self.ble.disconnect()
            except Exception as disconnect_error:
                logging.error(f"Disconnection Error: {disconnect_error}")

    def log_results(self, commands, last_logs, error):
        """Log results to CSV and console."""
        with open(self.results_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([str(commands), "\n".join(last_logs), error])

        print(f"Commands: {commands}, Last Logs: {last_logs}, Error: {error}")

async def main():
    ble_client = BLEClient()
    ble_client.init_logs()

    test_sequences = [
        ["OPEN"],
        ["CLOSE"],
        ["AUTH", "OPEN"],
        ["VALIDPASSCODE", "CLOSE"],
        ["AUTH", "OPEN", "CLOSE"],
        ["OPEN", "CLOSE"],
    ]

    state_machine = StateMachineFuzzer(ble_client, "Smart Lock [Group 7]")

    for sequence in test_sequences:
        await state_machine.run_state_machine(sequence)
        await asyncio.sleep(1)

def signal_handler(sig, frame):
    print("\nReceived interrupt signal. Cleaning up...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTesting stopped by user.")
