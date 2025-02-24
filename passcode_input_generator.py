import random

INPUT_FILE = "input_cases.txt"
FEEDBACK_FILE = "feedback_data.txt"

def generate_smart_fuzz_cases(num_cases=50):
    """ Generates new test cases based on past failures """
    test_cases = []

    # Load previous failures
    failed_cases = []
    try:
        with open(FEEDBACK_FILE, "r") as f:
            for line in f.readlines():
                data = line.strip().split(", ")
                if "Crash" in data[-1] or "Error Log" in data[-1]:
                    failed_cases.append(list(map(int, data[:-1])))
    except FileNotFoundError:
        pass

    for _ in range(num_cases):
        if failed_cases and random.random() < 0.5:
            # Mutate a previously failed case
            base_case = random.choice(failed_cases)
            mutation = [byte ^ random.randint(0, 0xFF) for byte in base_case]  # Bitwise mutation
            test_cases.append(mutation)
        else:
            # Generate a fresh random case
            length = random.randint(1, 20)
            passcode = [random.randint(0x00, 0xFF) for _ in range(length)]
            test_cases.append(passcode)

    with open(INPUT_FILE, "w") as f:
        for case in test_cases:
            f.write(",".join(map(str, case)) + "\n")

    print(f"[+] Generated {num_cases} new fuzz test cases in {INPUT_FILE}")

if __name__ == "__main__":
    generate_smart_fuzz_cases()
