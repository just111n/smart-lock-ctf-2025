import random
import hashlib
import os

def generate_invalid_commands():
    return [
        [random.randint(0, 255)],  # Single random byte
        [random.randint(0, 255) for _ in range(2)],
        [random.randint(0, 255) for _ in range(3)],
        [random.randint(0, 255) for _ in range(10)],
        [0x01],  # OPEN
        [0x01, 0x02],  # OPEN + CLOSE
    ]

def load_existing_crash_hashes(folder="crashes"):
    crash_hashes = set()
    for fname in os.listdir(folder):
        if fname.endswith(".txt"):  # Only read text-format saved crashes
            path = os.path.join(folder, fname)
            with open(path, "r") as f:
                content = f.read().strip()
                # Normalize spacing, remove brackets, etc. to hash consistently
                normalized = content.replace("[", "").replace("]", "").replace(",", "").replace(" ", "")
                crash_hashes.add(hashlib.md5(normalized.encode()).hexdigest())
    return crash_hashes