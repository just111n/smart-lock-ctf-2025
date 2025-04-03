#!/usr/bin/env python3
import os
import sys
import asyncio
import argparse
import time
import datetime
import logging
import subprocess
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SmartLock-Runner")

"""
Smart Lock Testing Tool
This script provides a convenient way to run both the test driver and fuzzer.
"""

# Default device name - modify this for your particular lock
DEVICE_NAME = "Smart Lock [Group 7]"

# Ensure the results directory exists
os.makedirs("results", exist_ok=True)


async def run_test_driver(device_name, test_type, repeat, output_dir):
    """Run the test driver with the specified parameters."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"test_results_{timestamp}.log")
    
    cmd = f"python test-driver.py --device '{device_name}' --test-type {test_type} --repeat {repeat}"
    logger.info(f"Running test driver: {cmd}")
    
    # Execute command
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Stream output in real-time
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        print(line.decode().strip())
    
    # Get any remaining output
    stdout, stderr = await process.communicate()
    
    if stdout:
        print(stdout.decode())
    if stderr:
        print(stderr.decode())
    
    # Save output to file
    with open(output_file, 'w') as f:
        f.write(f"Command: {cmd}\n")
        f.write(f"Date: {datetime.datetime.now()}\n\n")
        f.write(stdout.decode())
        if stderr:
            f.write("\nErrors:\n")
            f.write(stderr.decode())
    
    logger.info(f"Test driver results saved to {output_file}")
    return process.returncode


async def run_fuzzer(device_name, iterations, timeout, output_dir):
    """Run the fuzzer with the specified parameters."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"fuzzer_results_{timestamp}.log")
    
    cmd = f"python fuzzer.py --device '{device_name}' --iterations {iterations} --timeout {timeout}"
    logger.info(f"Running fuzzer: {cmd}")
    
    # Execute command
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Stream output in real-time
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        print(line.decode().strip())
    
    # Get any remaining output
    stdout, stderr = await process.communicate()
    
    if stdout:
        print(stdout.decode())
    if stderr:
        print(stderr.decode())
    
    # Save output to file
    with open(output_file, 'w') as f:
        f.write(f"Command: {cmd}\n")
        f.write(f"Date: {datetime.datetime.now()}\n\n")
        f.write(stdout.decode())
        if stderr:
            f.write("\nErrors:\n")
            f.write(stderr.decode())
    
    logger.info(f"Fuzzer results saved to {output_file}")
    return process.returncode


async def run_directed_tests(device_name, output_dir):
    """Run directed tests."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"directed_tests_{timestamp}.log")
    
    cmd = f"python fuzzer.py --device '{device_name}' --directed"
    logger.info(f"Running directed tests: {cmd}")
    
    # Execute command
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Stream output in real-time
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        print(line.decode().strip())
    
    # Get any remaining output
    stdout, stderr = await process.communicate()
    
    if stdout:
        print(stdout.decode())
    if stderr:
        print(stderr.decode())
    
    # Save output to file
    with open(output_file, 'w') as f:
        f.write(f"Command: {cmd}\n")
        f.write(f"Date: {datetime.datetime.now()}\n\n")
        f.write(stdout.decode())
        if stderr:
            f.write("\nErrors:\n")
            f.write(stderr.decode())
    
    logger.info(f"Directed test results saved to {output_file}")
    return process.returncode


def check_prerequisites():
    """Check if all required files exist."""
    required_files = ["fuzzer.py", "test-driver.py", "BLEClient.py"]
    missing_files = []
    
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        logger.error(f"Missing required files: {', '.join(missing_files)}")
        logger.error("Please ensure all necessary files are in the current directory.")
        return False
    
    return True


async def main():
    parser = argparse.ArgumentParser(description='Smart Lock Testing Tool')
    
    # Common arguments
    parser.add_argument('--device', '-d', default=DEVICE_NAME, help='BLE device name')
    parser.add_argument('--output-dir', '-o', default="results", help='Directory for output files')
    
    # Subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Running mode')
    
    # Test driver mode
    test_parser = subparsers.add_parser('test', help='Run test driver')
    test_parser.add_argument('--type', '-t', choices=['basic', 'protocol', 'sequence', 'fuzzy', 'all'], 
                             default='all', help='Type of test to run')
    test_parser.add_argument('--repeat', '-r', type=int, default=1, help='Number of times to repeat the test sequence')
    
    # Fuzzer mode
    fuzzer_parser = subparsers.add_parser('fuzz', help='Run fuzzer')
    fuzzer_parser.add_argument('--iterations', '-i', type=int, default=100, help='Maximum number of fuzzing iterations')
    fuzzer_parser.add_argument('--timeout', type=int, default=1800, help='Maximum runtime in seconds')
    
    # Directed tests mode
    directed_parser = subparsers.add_parser('directed', help='Run directed tests')
    
    # All-in-one mode
    all_parser = subparsers.add_parser('all', help='Run all test types in sequence')
    all_parser.add_argument('--iterations', '-i', type=int, default=50, help='Maximum number of fuzzing iterations')
    all_parser.add_argument('--timeout', type=int, default=100, help='Maximum runtime in seconds for fuzzing')
    
    args = parser.parse_args()
    
    # Check prerequisites
    if not check_prerequisites():
        return 1
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Run the selected mode
    if args.mode == 'test':
        return await run_test_driver(args.device, args.type, args.repeat, args.output_dir)
        
    elif args.mode == 'fuzz':
        return await run_fuzzer(args.device, args.iterations, args.timeout, args.output_dir)
        
    elif args.mode == 'directed':
        return await run_directed_tests(args.device, args.output_dir)
        
    elif args.mode == 'all':
        logger.info("=" * 70)
        logger.info("Running comprehensive test suite")
        logger.info("=" * 70)
        
        logger.info("STEP 1/3: Running directed tests")
        await run_directed_tests(args.device, args.output_dir)
        
        logger.info("\nSTEP 2/3: Running test driver with all test types")
        await run_test_driver(args.device, 'all', 1, args.output_dir)
        
        logger.info("\nSTEP 3/3: Running fuzzer")
        await run_fuzzer(args.device, args.iterations, args.timeout, args.output_dir)
        
        logger.info("=" * 70)
        logger.info(f"All tests completed. Results saved in {args.output_dir}")
        logger.info("=" * 70)
        return 0
    
    else:
        logger.info("Please specify a mode: test, fuzz, directed, or all")
        parser.print_help()
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("\nProgram Exited by User!")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        sys.exit(1)