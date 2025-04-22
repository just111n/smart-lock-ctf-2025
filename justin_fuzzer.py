# main_ble_fuzzer_copy.py
import logging
import asyncio
import random
import hashlib
import heapq
import os
import sys
from BLEClient import BLEClient
from ble_mutator_copy import mutate_input
from UserInterface import ShowUserInterface
from utils import generate_invalid_commands, load_existing_crash_hashes, create_seed_from_command,Seed,inverse_energy,exponential_energy
from typing import List, Dict, Set, Tuple, Any, Optional
import time

DEVICE_NAME = "Smart Lock [Group 7]"
CRASH_DIR = "crashes"
INTERESTING_DIR = "interesting"

# Commands
AUTH = [0x00]
OPEN = [0x01]
CLOSE = [0x02]
DEFAULT_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Default passcode

WRONG_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong passcode

# Define interesting test scenarios
# SEED_COMMAND_SEQUENCES:List[List[List[int]]] = [

#     # # SPECIAL
#     [[0xAA,0xAA]],

#     # Edge cases exploration
#     [[0x00]],  # AUTH without passcode
#     [[0x03]],  # Unknown command (off-by-one from CLOSE)
#     [[0xFF]],  # Invalid command (maximum value)
#     [AUTH + DEFAULT_PASSCODE[:3]],  # AUTH with incomplete passcode

    

#     # Locked
#     [AUTH + DEFAULT_PASSCODE],
#     [CLOSE], 
    

#     # TODO: Authenticating

#     # Authenticated
#     [AUTH + DEFAULT_PASSCODE,OPEN],
#     [AUTH + DEFAULT_PASSCODE,CLOSE],

#     # TODO: Opening

#     # TODO: Unlocked
#     [AUTH + DEFAULT_PASSCODE,OPEN,OPEN],
#     [AUTH + DEFAULT_PASSCODE,OPEN,CLOSE],

#     # # # TODO: Closing

    

#     # Basic protocol tests
#     [AUTH + DEFAULT_PASSCODE],  # Valid authentication
#     [OPEN],                     # Open command
#     [CLOSE],                    # Close command
    
#     # State transition sequences
#     [AUTH + DEFAULT_PASSCODE , OPEN],  # Auth + Open
#     [AUTH + DEFAULT_PASSCODE , CLOSE], # Auth + Close
    
#     # Command sequences in a single frame
#     [OPEN , CLOSE],            # Open then Close
#     [CLOSE , OPEN],            # Close then Open
#     [OPEN , OPEN],             # Open twice
#     [CLOSE , CLOSE],           # Close twice
    
#     # Complex state transition sequences
#     [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE], # Auth + Open + Close
#     [AUTH + DEFAULT_PASSCODE , CLOSE , OPEN], # Auth + Close + Open
    
#     # Double authentication scenarios (potential bugs)
#     [AUTH + DEFAULT_PASSCODE , AUTH + DEFAULT_PASSCODE],
    
#     # Full sequences
#     [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE , OPEN , CLOSE],
    
#     # Edge cases exploration
#     [[0x00]],  # AUTH without passcode
#     [[0x03]],  # Unknown command (off-by-one from CLOSE)
#     [[0xFF]],  # Invalid command (maximum value)
#     [AUTH + DEFAULT_PASSCODE[:3]],  # AUTH with incomplete passcode
# ]
SEED_COMMAND_SEQUENCES:List[List[List[int]]] = [

    # # SPECIAL
    [[0x3F,0x3F,0x3F]],
    # [[0x3F]+DEFAULT_PASSCODE]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x01],[0x0A],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x01],[0x01],[0x02],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x0A],[0x0A],[0xFF, 0xFF, 0xFF, 0xFF],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],],
    [AUTH + DEFAULT_PASSCODE,OPEN,[0x0A],CLOSE],
    [OPEN , CLOSE],            # Open then Close
    # Command sequences in a single frame
    [OPEN , CLOSE],            # Open then Close
    [CLOSE , OPEN],            # Close then Open
    [OPEN , OPEN],             # Open twice
    [CLOSE , CLOSE],           # Close twice
    [[0x0A],[0xFF]*4],
    
    
    
    
    # Complex state transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE], # Auth + Open + Close
    [AUTH + DEFAULT_PASSCODE , CLOSE , OPEN], # Auth + Close + Open
    
    # Double authentication scenarios (potential bugs)
    [AUTH + DEFAULT_PASSCODE , AUTH + DEFAULT_PASSCODE],
    
    # Full sequences
    [AUTH + DEFAULT_PASSCODE , OPEN , CLOSE , OPEN , CLOSE],
    # Basic protocol tests
    [AUTH + DEFAULT_PASSCODE],  # Valid authentication
    [OPEN],                     # Open command
    [CLOSE],                    # Close command
    
    # State transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN],  # Auth + Open
    [AUTH + DEFAULT_PASSCODE , CLOSE], # Auth + Close
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]],
    
    
    # Basic protocol tests
    [AUTH + DEFAULT_PASSCODE],  # Valid authentication
    [OPEN],                     # Open command
    [CLOSE],                    # Close command
    
    # State transition sequences
    [AUTH + DEFAULT_PASSCODE , OPEN],  # Auth + Open
    [AUTH + DEFAULT_PASSCODE , CLOSE], # Auth + Close
    
    
    
    # Edge cases exploration
    [[0x00]],  # AUTH without passcode
    [[0x03]],  # Unknown command (off-by-one from CLOSE)
    [[0xFF]],  # Invalid command (maximum value)
    
    [AUTH + DEFAULT_PASSCODE[:3]],  # AUTH with incomplete passcode

    [[0x3F]],
    [[0xAA]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],[0x02],[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]],
    [AUTH + WRONG_PASSCODE , OPEN],  # Auth + Open
    [AUTH + WRONG_PASSCODE , CLOSE], # Auth + Close
    [[0xFF]*4],  # Invalid command (maximum value)
    [[0xAA,0xAA]],
    
    [AUTH + DEFAULT_PASSCODE , OPEN+CLOSE],  # Auth + Open
    [[0x04],[0x04],[0x04],[0x04],[0x04]],
    [[0x0B]],
]

#  ================= Global variables ================= 
response_codes_seen = set()
logging_seed = None
ble_connection_count = 0
expected_responses = [[0x00], [0x01], [0x02],[0x03],[0x04]]
seen_combinations = set()
mutated_seed_count = 0
seed_input_count = 0
seed_queue:List[Seed] = []
failure_queue:List[Seed] = []


# ===================================

os.makedirs(CRASH_DIR, exist_ok=True)
os.makedirs(INTERESTING_DIR, exist_ok=True)



# ============= Fuzzer Functions =============
def choose_next(seed_queue) -> Optional[Seed]:
    """Choose the next input to test based on priority."""
    if not seed_queue: 
        return None
        
    # Get the highest priority seed (lowest priority value)
    seed = heapq.heappop(seed_queue)
    seed.execution_count += 1
        
    return seed



def assign_energy(seed: Seed,energy_function) -> float:
        """Assign energy to a seed based on how promising it seems."""

        # Re-compute energy based on execution count
        seed.energy = energy_function(seed.execution_count)
        
        energy = seed.energy
        # Adjust energy based on path weight if available
        # if seed.path_hash in self.path_tracker.path_weights:
        #     path_weight = self.path_tracker.path_weights[seed.path_hash]
        #     energy *= path_weight
        
        # Seeds that led to crashes get extra energy
        if seed.is_error_detected:
            energy *= 3.0
        
        # Seeds with error response codes get extra energy
        if seed.response and seed.response[0] != 0:
            energy *= 1.5
        
        # Prioritize complex command sequences
        if len(seed.data) > 2:
            energy *= 1.2
            
        return energy

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
        if actual_response[0] != 0:
            print("Authentication failed with the correct passcode!")
            seed.is_error_detected = True
            seed.error_code = actual_response
            print("STOPPPPP")
            return True

    return False



def is_interesting(
    seed: Seed,
    seen_combinations: Set[Tuple[str, str]],
    response_codes_seen: Set[int],
) -> bool:
    """
    Determines if a seed is 'interesting' based on:
    - New input/output (path/response) combinations.
    - New/unseen response codes.
    - Long or complex sequences.
    """
    path_hash = seed.path_hash
    response_hash = seed.response_hash
    hash_pair = (path_hash, response_hash)

    

    if seed.response:
        status = seed.response[0]
        
        if status not in response_codes_seen:
            response_codes_seen.add(status)
            return True
        
    if hash_pair not in seen_combinations:
        seen_combinations.add(hash_pair)
        return True

    # if len(seed.data) > 5:
    #     return True

    return False

def assign_path_weights(seed: Seed) -> float:
    global response_codes_seen
    """
    Assigns a custom priority to a seed based on its level of 'interestingness'.
    Lower value = higher priority in the seed queue.
    """

    # Highest priority: if it caused an error or crash
    if seed.response not in response_codes_seen:
        return 0.2

    # Moderate: unique non-zero response (unexpected behavior)
    # if seed.response and seed.response[0] != 0x00:
    #     return 0.3

    # Medium-low: long sequences could trigger latent state bugs
    # if len(seed.data) > 5:
    #     return 0.5

    # Default interesting priority
    return 1.0




def save_to(folder: str, seed:Seed, ble_last_log:str) -> None:
    """
    Save the seed's data into a structured folder by parent hash.
    """
    # os.makedirs(folder, exist_ok=True)

    parent_folder = seed.parent_hash or "initial_seed"
    full_folder_path = os.path.join(folder, parent_folder)
    os.makedirs(full_folder_path, exist_ok=True)

    # Generate filename from flattened command hex
    filename = f"{seed.path_hash}.txt"
    path = os.path.join(full_folder_path, filename)

    print(f"Saving to {path}")

    with open(path, "w", encoding="utf-8") as f:

        f.write(f"=== Fuzzed BLE Input ===\n")

        # Write the raw 2D command data
        f.write(f"\n--- 2D Command Sequence ---\n")
        for i, cmd in enumerate(seed.data):
            hex_cmd = ", ".join(f"0x{b:02X}" for b in cmd)
            f.write(f"[{hex_cmd}],")

        f.write(f"\n")

        f.write("\n--- BLE Log ---\n")
        
        f.write(ble_last_log + "\n")

        f.write(f"=== Fuzzed BLE Input ===\n")
        f.write(f"Timestamp       : {time.ctime(seed.timestamp)}\n")
        f.write(f"Execution Count : {seed.execution_count}\n")
        f.write(f"Priority        : {seed.priority:.4f}\n")
        f.write(f"Energy          : {seed.energy:.4f}\n")
        f.write(f"Mutation Note   : {seed.mutation_note}\n")
        f.write(f"Parent Hash     : {seed.parent_hash}\n")
        f.write(f"Path Hash       : {seed.path_hash}\n")
        f.write(f"Error Detected  : {seed.is_error_detected}\n")
        f.write(f"Error Code      : {seed.error_code}\n")
        f.write(f"Response        : {[f'0x{b:02X}' for b in seed.response]}\n")
        f.write(f"Response Hash   : {seed.response_hash}\n")
        f.write(f"number_of_commands_executed: {seed.number_of_commands_executed}\n")
        
      

        f.write("\n--- Seed Logs ---\n")
        for log in seed.logs:
            f.write(log + "\n")
        
        

        

        f.write("\n--- Reproduction Code ---\n")
        f.write("```python\n")
        f.write("from BLEClient import BLEClient\n")
        f.write("ble = BLEClient()\n")
        f.write("ble.init_logs()\n")
        f.write(f"await ble.connect(\"{DEVICE_NAME}\")\n")
        f.write(f"# Re-send command sequence\n")
        for cmd in seed.data:
            f.write(f"await ble.write_command({cmd})\n")
            f.write(f"await asyncio.sleep(2)\n")      
        f.write("logs = ble.read_logs()\n")
        f.write("for log in logs:\n")
        f.write("    print(log)\n")
        f.write("```\n")






async def main():
    global seed_input_count
    global mutated_seed_count
    global logging_seed
    global ble_connection_count
    global expected_responses
    global seen_combinations
    global response_codes_seen
    global seed_queue
    global failure_queue
    
    # print("Getting Seed inputs from seed command sequences")
    SEED_INPUTS = [
    create_seed_from_command(seq, note=f"Predefined test #{i}")
    for i, seq in enumerate(SEED_COMMAND_SEQUENCES)
    ] 
    print(f"Found {len(SEED_INPUTS)} seed inputs.")

    # print("Inserting Seed Inputs into Seed Queue")
    for seed in SEED_INPUTS:
        heapq.heappush(seed_queue, seed)

    print("Initializing BLE client...")
    ble = BLEClient()
    ble.init_logs()
    print(f"[1] Connecting to '{DEVICE_NAME}'...")
    await ble.connect(DEVICE_NAME)
    await asyncio.sleep(1)

    ble_connection_count += 1

    logging_seed = Seed(
        priority=1.0,
        energy=1.0,
        data=[],
        path_hash=str(ble_connection_count), ## Use connection count as path hash
        mutation_note="Logging seed",
        logs=[]
    )

    

    # logging_seed = Seed(
    #     priority=1.0,
    #     energy=1.0,
    #     data=[AUTH + DEFAULT_PASSCODE],
    #     path_hash=str(ble_connection_count),
    #     mutation_note="Logging seed",
    #     logs=[]
    # )

    # print("\n[2] Authenticating...")
    # res = await ble.write_command(AUTH + DEFAULT_PASSCODE)
    # if res[0] != 0:
    #     print(f"[X] Failure: Wrong Passcode.")
    #     await ble.disconnect()
    #     return
    

    

    print("Starting BLE Fuzzer...")

    

    try:
        while seed_queue:

            current_seed: Seed = choose_next(seed_queue)

            if current_seed is None:
                print("No more seeds to test.")
                break
            
            
            seed_input_count += 1
            print(f"{'='*25} Seed Input {seed_input_count} {'='*25}")

            # TODO: randomize Energy function
            energy = assign_energy(current_seed, exponential_energy)


            # Run multiple mutations on each mutated seed based on energy
            for _ in range(max(1, int(energy * 5))): 
            # for _ in range(1):  # Run mutations once for each seed
                
                # Controlled randomness
                custom_rng = random.Random(52)  # Use a fixed seed for reproducibility  
                mutated_data = mutate_input(current_seed)
                # Run mutation
                mutated_data = mutate_input(
                    current_seed,
                    mutation_weights={
                        'command_flip': 0.1,
                        'sequence_shuffle': 0.3,
                        'command_insert': 0.1,
                        'sequence_duplicate': 0.5
                    },
                    bitflip_range=(1, 255),
                    truncation_prob=0,
                    extension_prob=0.2,
                    max_extend_bytes=10,
                    rng=custom_rng
                )
                

                # Genenrate a new path hash for the mutated data
                # Step 1: Initialize an empty list to hold all bytes
                flattened = []
                    # Step 2: Iterate over each command in the sequence
                for cmd in mutated_data:
                    # Each cmd is a list of bytes, extend the flattened list
                    flattened.extend(cmd)
                    # Step 3: Convert the flattened list into a bytes object
                flat_bytes = bytes(flattened)
                    # Step 4: Generate a SHA-256 hash as the path hash
                path_hash = hashlib.sha256(flat_bytes).hexdigest()

                    
                mutated_seed = Seed(
                    priority=1.0,
                    energy=energy,
                    data=mutated_data,
                    parent_hash=current_seed.path_hash,
                    path_hash= path_hash,
                    mutation_note="mutation",
                    timestamp=time.time(),
                    
                    logs=[]
                    )

                mutated_seed_count += 1
                print(f"Starting Mutated Seed {mutated_seed_count} Sequence")
                    
                    

                try:
                    for command in mutated_seed.data:
                        mutated_seed.logs.append(f"Sent: {[hex(b) for b in command]}")
                        logging_seed.logs.append(f"Sent: {[hex(b) for b in command]}")
                        logging_seed.data.append(command)
                    
                      
                        mutated_seed.number_of_commands_executed += 1


                        response = await ble.write_command(command)                             
                        # await asyncio.sleep(1)

                        mutated_seed.response = bytes(response)
                        mutated_seed.response_hash = hashlib.sha256(mutated_seed.response).hexdigest()
                        mutated_seed.execution_count = 1

                        mutated_seed.logs.append(f"Received: {[hex(b) for b in response]}")
                        logging_seed.logs.append(f"Received: {[hex(b) for b in command]}")

                                
                        mutated_seed.error_code = response
                        lines = ble.read_logs()

                        if is_error(mutated_seed,command,response, expected_responses):
                            mutated_seed.is_error_detected = True
                            mutated_seed.logs.append(f"⚠️ Error detected by is_error function, response: {response}")
                            failure_queue.append(mutated_seed)
                            save_to("crashes", mutated_seed, lines[-1])
                            
                            break

                                # res = await ble.write_command(AUTH + DEFAULT_PASSCODE)
                                # await asyncio.sleep(2)
                                # if res[0] != 0:
                                #     print(f"[X] Failure: Wrong Passcode.")
                                #     await ble.disconnect()
                                #     return
                                    
                            
                    if is_interesting(mutated_seed, seen_combinations, response_codes_seen):
                        mutated_seed.is_interesting = True
                        mutated_seed.logs.append("🌟 Interesting seed: new behavior or output")

                        # Assign priority based on how interesting it is
                        mutated_seed.priority = assign_path_weights(mutated_seed)

                        lines = ble.read_logs()
                        save_to("interesting", mutated_seed, lines[-1])
                        heapq.heappush(seed_queue, mutated_seed)





                except Exception as e:
                    # To catch errors that crash the fuzzer
                    print(f"⚠️ Error sending command: {e}")
                    mutated_seed.logs.append(f"Error Response Received!")
                    logging_seed.logs.append(f"Error Response Received!")
                    logging_seed.is_error_detected = True
                    failure_queue.append(logging_seed)

                    lines = ble.read_logs()
                        

                    save_to("crashes", mutated_seed,lines[-1]) 
                    save_to("logging", logging_seed,lines[-1])   
                    print("Disconnecting...")
                    await ble.disconnect()
                    await asyncio.sleep(1)
                    print(f"[1] Connecting to '{DEVICE_NAME}'...")
                    await ble.connect(DEVICE_NAME)
                    await asyncio.sleep(1)
                    # Get a new logging_seed
                    ble_connection_count += 1
                    logging_seed = Seed(timestamp=time.time(), logs=[], priority=1.0, energy=1.0, data=[],path_hash=str(ble_connection_count), mutation_note="Logging seed")



                    # logging_seed = Seed(timestamp=time.time(), logs=[], priority=1.0, energy=1.0, data=[AUTH + DEFAULT_PASSCODE],path_hash=str(ble_connection_count), mutation_note="Logging seed")

                    # print("\n[2] Authenticating...")
                    # res = await ble.write_command(AUTH + DEFAULT_PASSCODE)
                    # if res[0] != 0:
                    #     print(f"[X] Failure: Wrong Passcode.")
                    #     await ble.disconnect()
                    #     return

                    continue

                
                # print("\nTesting Authentication...")
                # logging_seed.logs.append(f"Received: {[hex(b) for b in command]}")
                # res = await ble.write_command(AUTH + DEFAULT_PASSCODE)
                # await asyncio.sleep(1)
                # print(f"Authentication Response: {res}\n")
                # if res[0] != 0:
                #     print(f"Authentication Fails with correct passcode.")
                    
                        

                    


    except Exception as e:
        print(f"⚠️ Fuzzer error: {e}")

    # =========== Ending ==========
    finally:
        await ble.disconnect()
        print("[!] Fuzzing session ended.")
        lines = ble.read_logs()

        with open("ble_logs.txt", "w", encoding="utf-8") as f:
            f.write("=== BLE LOGS ===\n\n")
            for line in lines:
                f.write(line + "\n")

        print(f"No. of seed inputs processed: {seed_input_count}")
        print(f"No. of mutated seeds processed: {mutated_seed_count}")
        # Print out my global variables
        print(f"BLE connection count: {ble_connection_count}")
        print(f"Seen combinations: {len(seen_combinations)}")
        print(f"Seen response codes: {len(response_codes_seen)}")
        print(response_codes_seen)
        print(f"seedqueue length: {len(seed_queue)}")
        print(f"failure_queue length: {len(failure_queue)}")
        
        # make a file that contains all the error and analysis
                # Save statistics to a separate test analysis coverage summary file
        with open("test_coverage_summary.txt", "w", encoding="utf-8") as summary:
            summary.write("=== BLE Fuzzer Coverage Summary ===\n")
            summary.write(f"Timestamp                  : {time.ctime()}\n")
            summary.write(f"No. of seed inputs         : {seed_input_count}\n")
            summary.write(f"No. of mutated seeds       : {mutated_seed_count}\n")
            summary.write(f"BLE connections made       : {ble_connection_count}\n")
            summary.write(f"Unique path-response pairs : {len(seen_combinations)}\n")
            summary.write(f"Unique response codes      : {len(response_codes_seen)}\n")
            summary.write(f"Response codes seen        : {sorted(response_codes_seen)}\n")
            summary.write(f"Remaining seeds in queue   : {len(seed_queue)}\n")
            summary.write(f"Failure queue size         : {len(failure_queue)}\n")

        # Save failure seeds individually into "failureQueue/" folder
        os.makedirs("failureQueue", exist_ok=True)
        for i, failed_seed in enumerate(failure_queue):
            file_name = f"failure_{i+1}_{failed_seed.path_hash[:8]}.txt"
            file_path = os.path.join("failureQueue", file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("=== Failed Seed ===\n")
                f.write(f"Timestamp       : {time.ctime(failed_seed.timestamp)}\n")
                f.write(f"Path Hash       : {failed_seed.path_hash}\n")
                f.write(f"Parent Hash     : {failed_seed.parent_hash}\n")
                f.write(f"Error Detected  : {failed_seed.is_error_detected}\n")
                f.write(f"Error Code      : {failed_seed.error_code}\n")
                f.write(f"Priority        : {failed_seed.priority:.4f}\n")
                f.write(f"Energy          : {failed_seed.energy:.4f}\n")
                f.write(f"Mutation Note   : {failed_seed.mutation_note}\n")
                f.write(f"Commands Sent   :\n")
                for cmd in failed_seed.data:
                    f.write(f"  {[f'0x{b:02X}' for b in cmd]}\n")
                f.write(f"\nLogs:\n")
                for log in failed_seed.logs:
                    f.write(f"{log}\n")

        sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
        
