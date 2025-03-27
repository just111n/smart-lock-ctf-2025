def is_crash(serial_log):
    crash_keywords = [
        "error",         # matches [Error] Code...
        "panic",         # Guru Meditation panic
        "reset",         # device restart
        "exception",     # uncaught exception
        "guru",          # Guru Meditation
        "assert",        # assert failure
        "overflow",      # stack or buffer overflow
        "core panic"     # ESP32 core crash
    ]
    
    # Check the last 10–20 lines for any keyword
    for line in serial_log[-100:]:
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in crash_keywords):
            return True
    return False


def is_interesting(response, seen_paths):
    return str(response) not in seen_paths
