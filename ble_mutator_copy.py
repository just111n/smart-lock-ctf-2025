import random
from typing import List, Dict, Tuple, Optional
from utils import Seed

# ------------------------------
# Helper Functions for Mutation
# ------------------------------

def flip_random_byte(command: List[int], rng: random.Random, bitflip_range: Tuple[int, int]) -> None:
    if command:
        byte_idx = rng.randint(0, len(command) - 1)
        flip_val = rng.randint(*bitflip_range)
        command[byte_idx] ^= flip_val


def insert_random_byte(command: List[int], rng: random.Random) -> None:
    byte_idx = rng.randint(0, len(command)) if command else 0
    command.insert(byte_idx, rng.randint(0, 255))


def delete_random_byte(command: List[int], rng: random.Random) -> None:
    if len(command) > 1:
        byte_idx = rng.randint(0, len(command) - 1)
        del command[byte_idx]


def shuffle_commands(sequence: List[List[int]], rng: random.Random) -> None:
    rng.shuffle(sequence)


def duplicate_command(sequence: List[List[int]], rng: random.Random) -> None:
    cmd_idx = rng.randint(0, len(sequence) - 1)
    sequence.insert(cmd_idx, sequence[cmd_idx].copy())


def remove_random_command(sequence: List[List[int]], rng: random.Random) -> None:
    if len(sequence) > 1:
        del sequence[rng.randint(0, len(sequence) - 1)]


def truncate_commands(sequence: List[List[int]], rng: random.Random) -> None:
    for cmd in sequence:
        if len(cmd) > 1:
            cmd[:] = cmd[:rng.randint(1, len(cmd))]


def extend_last_command(sequence: List[List[int]], rng: random.Random, max_extend_bytes: int) -> None:
    if sequence:
        sequence[-1].extend([rng.randint(0, 255) for _ in range(rng.randint(1, max_extend_bytes))])

# ------------------------------
# Main Mutation Function
# ------------------------------

def mutate_input(
    seed: Seed,
    mutation_weights: Optional[Dict[str, float]] = None,
    bitflip_range: Tuple[int, int] = (1, 255),
    truncation_prob: float = 0.1,
    extension_prob: float = 0.1,
    max_extend_bytes: int = 50,
    rng: Optional[random.Random] = None
) -> List[List[int]]:
    """
    Controlled mutation of a 2D list of BLE commands.
    """
    rng = rng or random
    command_sequence = seed.data
    mutated_sequence = [cmd.copy() for cmd in command_sequence]

    if not mutated_sequence:
        return []

    # Default mutation weights
    weights = mutation_weights or {
        'command_flip': 0.3,
        'command_insert': 0.15,
        # 'command_delete': 0.15,
        'sequence_shuffle': 0.1,
        'sequence_duplicate': 0.15,
        # 'sequence_remove': 0.15,
    }

    mutation_type = rng.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
    seed.mutation_note = mutation_type

    if mutation_type == 'command_flip':
        flip_random_byte(rng.choice(mutated_sequence), rng, bitflip_range)
    elif mutation_type == 'command_insert':
        insert_random_byte(rng.choice(mutated_sequence), rng)
    # elif mutation_type == 'command_delete':
    #     delete_random_byte(rng.choice(mutated_sequence), rng)
    elif mutation_type == 'sequence_shuffle':
        shuffle_commands(mutated_sequence, rng)
    elif mutation_type == 'sequence_duplicate':
        duplicate_command(mutated_sequence, rng)
    # elif mutation_type == 'sequence_remove':
    #     remove_random_command(mutated_sequence, rng)

    # if rng.random() < truncation_prob:
    #     truncate_commands(mutated_sequence, rng)

    if rng.random() < extension_prob:
        extend_last_command(mutated_sequence, rng, max_extend_bytes)

    return mutated_sequence