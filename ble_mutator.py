import random

def mutate_command(command_bytes):
    mutation_type = random.choice(["bitflip", "insert", "delete", "duplicate", "swap"])
    mutated = bytearray(command_bytes)

    if mutation_type == "bitflip":
        idx = random.randint(0, len(mutated) - 1)
        mutated[idx] ^= 0x01

    elif mutation_type == "insert":
        mutated.insert(random.randint(0, len(mutated)), random.randint(0, 255))

    elif mutation_type == "delete" and len(mutated) > 1:
        mutated.pop(random.randint(0, len(mutated) - 1))

    elif mutation_type == "duplicate":
        mutated += mutated

    elif mutation_type == "swap" and len(mutated) > 1:
        i, j = random.sample(range(len(mutated)), 2)
        mutated[i], mutated[j] = mutated[j], mutated[i]

    return bytes(mutated)
