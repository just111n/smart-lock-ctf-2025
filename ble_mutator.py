import random

def mutate_command(cmd):
    mutated = bytearray(cmd)

    # Choose mutation type
    mutation_type = random.choice(['flip', 'insert', 'delete', 'duplicate', 'replace'])

    if mutation_type == 'flip' and len(mutated) > 0:
        idx = random.randint(0, len(mutated) - 1)
        mutated[idx] ^= random.randint(1, 255)

    elif mutation_type == 'insert':
        idx = random.randint(0, len(mutated))  # insert at any position
        mutated.insert(idx, random.randint(0, 255))

    elif mutation_type == 'delete' and len(mutated) > 1:
        idx = random.randint(0, len(mutated) - 1)
        del mutated[idx]

    elif mutation_type == 'duplicate' and len(mutated) > 0:
        idx = random.randint(0, len(mutated) - 1)
        mutated.insert(idx, mutated[idx])

    elif mutation_type == 'replace' and len(mutated) > 0:
        idx = random.randint(0, len(mutated) - 1)
        mutated[idx] = random.randint(0, 255)

    # Random truncation with small chance
    if len(mutated) > 1 and random.random() < 0.1:
        mutated = mutated[:random.randint(1, len(mutated))]

    # Random extension with small chance
    if random.random() < 0.1:
        mutated.extend([random.randint(0, 255) for _ in range(random.randint(1, 3))])

    return mutated
