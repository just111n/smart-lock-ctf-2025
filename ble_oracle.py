def is_crash(serial_log):
    keywords = ["panic", "reset", "Guru", "exception", "assert", "overflow"]
    return any(any(word in line.lower() for word in keywords) for line in serial_log[-10:])

def is_interesting(response, seen_paths):
    return str(response) not in seen_paths
