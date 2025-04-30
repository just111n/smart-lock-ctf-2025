# To Run Fuzzer for BLE smartlock

```bash
./fuzz.bat
```

## Result Folders Explained

logging/initial_seed/: Contains raw seed files and logs showing which commands from the initial corpus led to crashes.

failureQueue/: Stores mutated command sequences that produced failures or unexpected responses without a full crash.

interesting/: Contains seeds flagged as interesting, typically due to new coverage, unusual timing, or partial successes.

bugs/: Houses seeds that consistently reproduce identified bugs in the target device.

crashes/: Includes seeds that cause the device to crash, disconnect, or become unresponsive.

Coverage Summary saved to 'test_coverage_summary.txt'

BLE logs saved to 'ble_logs.txt'