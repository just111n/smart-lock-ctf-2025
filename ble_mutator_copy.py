import random
from typing import List
from utils import Seed

def mutate_input(seed: Seed) -> List[List[int]]:
    """
    Mutates a 2D list of commands (each command is a list of bytes).
    Applies mutation at both the command level and sequence level.
    """
    command_sequence = seed.data
    mutated_sequence = [cmd.copy() for cmd in command_sequence]  # Deep copy

    if not mutated_sequence:
        return []

    # Choose mutation type: command-level or sequence-level
    mutation_type = random.choice(['command_flip', 'command_insert', 'command_delete',
                                   'sequence_shuffle', 'sequence_duplicate', 'sequence_remove'])
    seed.mutation_note = mutation_type

    if mutation_type == 'command_flip':
        cmd_idx = random.randint(0, len(mutated_sequence) - 1)
        if mutated_sequence[cmd_idx]:
            byte_idx = random.randint(0, len(mutated_sequence[cmd_idx]) - 1)
            mutated_sequence[cmd_idx][byte_idx] ^= random.randint(1, 255)

    elif mutation_type == 'command_insert':
        cmd_idx = random.randint(0, len(mutated_sequence) - 1)
        byte_idx = random.randint(0, len(mutated_sequence[cmd_idx])) if mutated_sequence[cmd_idx] else 0
        mutated_sequence[cmd_idx].insert(byte_idx, random.randint(0, 255))

    elif mutation_type == 'command_delete':
        cmd_idx = random.randint(0, len(mutated_sequence) - 1)
        if len(mutated_sequence[cmd_idx]) > 1:
            byte_idx = random.randint(0, len(mutated_sequence[cmd_idx]) - 1)
            del mutated_sequence[cmd_idx][byte_idx]

    elif mutation_type == 'sequence_shuffle' and len(mutated_sequence) > 1:
        random.shuffle(mutated_sequence)

    elif mutation_type == 'sequence_duplicate':
        cmd_idx = random.randint(0, len(mutated_sequence) - 1)
        mutated_sequence.insert(cmd_idx, mutated_sequence[cmd_idx].copy())

    elif mutation_type == 'sequence_remove' and len(mutated_sequence) > 1:
        del mutated_sequence[random.randint(0, len(mutated_sequence) - 1)]

    # Optional: add rare truncation or extension
    if random.random() < 0.1:
        # Truncate a command
        for cmd in mutated_sequence:
            if len(cmd) > 1:
                cmd[:] = cmd[:random.randint(1, len(cmd))]

    if random.random() < 0.1:
        # Extend the last command slightly
        if mutated_sequence:
            mutated_sequence[-1].extend([random.randint(0, 255) for _ in range(random.randint(1, 2))])

    return mutated_sequence
