import random

def generate_invalid_commands():
    return [
        [random.randint(0, 255)],  # Single random byte
        [random.randint(0, 255) for _ in range(2)],
        [random.randint(0, 255) for _ in range(3)],
        [random.randint(0, 255) for _ in range(10)],
        [0x01],  # OPEN
        [0x01, 0x02],  # OPEN + CLOSE
    ]
