import random
from typing import List, Dict
from utils import Seed

def mutate_input(
    seed: Seed,
    mutation_weights: Dict[str, float] = None,
    bitflip_range: tuple = (1, 255),
    truncation_prob: float = 0.1,
    extension_prob: float = 0.1,
    max_extend_bytes: int = 2,
    rng: random.Random = None
) -> List[List[int]]:
    """
    Controlled mutation of a 2D list of BLE commands.
    
    Args:
        seed: The original seed input.
        mutation_weights: Dict of mutation types and their selection weights.
        bitflip_range: Tuple specifying bitflip value range.
        truncation_prob: Probability of truncating a command.
        extension_prob: Probability of extending a command.
        max_extend_bytes: Max random bytes to append if extension is triggered.
        rng: Optional random.Random instance for deterministic testing.

    Returns:
        A mutated 2D command sequence.
    """
    rng = rng or random
    command_sequence = seed.data
    mutated_sequence = [cmd.copy() for cmd in command_sequence]

    if not mutated_sequence:
        return []

    # Default mutation weights
    default_weights = {
        'command_flip': 0.3,
        'command_insert': 0.15,
        'command_delete': 0.15,
        'sequence_shuffle': 0.1,
        'sequence_duplicate': 0.15,
        'sequence_remove': 0.15,
    }
    weights = mutation_weights or default_weights

    mutation_type = rng.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
    seed.mutation_note = mutation_type

    if mutation_type == 'command_flip':
        cmd_idx = rng.randint(0, len(mutated_sequence) - 1)
        if mutated_sequence[cmd_idx]:
            byte_idx = rng.randint(0, len(mutated_sequence[cmd_idx]) - 1)
            flip_val = rng.randint(*bitflip_range)
            mutated_sequence[cmd_idx][byte_idx] ^= flip_val

    elif mutation_type == 'command_insert':
        cmd_idx = rng.randint(0, len(mutated_sequence) - 1)
        byte_idx = rng.randint(0, len(mutated_sequence[cmd_idx])) if mutated_sequence[cmd_idx] else 0
        mutated_sequence[cmd_idx].insert(byte_idx, rng.randint(0, 255))

    elif mutation_type == 'command_delete':
        cmd_idx = rng.randint(0, len(mutated_sequence) - 1)
        if len(mutated_sequence[cmd_idx]) > 1:
            byte_idx = rng.randint(0, len(mutated_sequence[cmd_idx]) - 1)
            del mutated_sequence[cmd_idx][byte_idx]

    elif mutation_type == 'sequence_shuffle' and len(mutated_sequence) > 1:
        rng.shuffle(mutated_sequence)

    elif mutation_type == 'sequence_duplicate':
        cmd_idx = rng.randint(0, len(mutated_sequence) - 1)
        mutated_sequence.insert(cmd_idx, mutated_sequence[cmd_idx].copy())

    elif mutation_type == 'sequence_remove' and len(mutated_sequence) > 1:
        del mutated_sequence[rng.randint(0, len(mutated_sequence) - 1)]

    # Optional: truncate commands
    if rng.random() < truncation_prob:
        for cmd in mutated_sequence:
            if len(cmd) > 1:
                cmd[:] = cmd[:rng.randint(1, len(cmd))]

    # Optional: extend the last command
    if rng.random() < extension_prob:
        if mutated_sequence:
            mutated_sequence[-1].extend([rng.randint(0, 255) for _ in range(rng.randint(1, max_extend_bytes))])

    return mutated_sequence
