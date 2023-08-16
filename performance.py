import time
import tracemalloc
from r8edsa import R8EDSA
from concurrent.futures import ThreadPoolExecutor

RSA_KEY_LENGTHS = [512, 1024, 2048]
SAMPLE_SIZES = [10, 50, 100, 250]
MESSAGES = ["test", "message", "encrypted message", "this is a test message", "quantum123", "robert", "someSecretKey42"]
totalTests = len(RSA_KEY_LENGTHS) * len(SAMPLE_SIZES) * len(MESSAGES)
progress = 0

def run_algorithm_test(message, rsa_key_length, sample_size):
    global progress
    try:
        # Measure memory before the algorithm starts
        tracemalloc.start()
        start_current, _ = tracemalloc.get_traced_memory()
        
        # Algorithm execution
        start_time = time.time()
        r8edsa = R8EDSA(message, rsa_key_length, sample_size)
        r8edsa.execute_r8edsa()
        end_time = time.time()

        # Measure memory after the algorithm ends
        end_current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        execution_time = end_time - start_time
        speed = len(message) / execution_time

        # Calculate the actual memory used by the algorithm
        actual_memory_used = (end_current - start_current) / 10**6

        progress += 1
        print(f"Running {progress} tests out of {totalTests}")
        
        # Return the result
        return {
            "message": f"Testing message length {len(message)}, key length {rsa_key_length} and sample size {sample_size}",
            "parameters": {
                "message_length": len(message),
                "rsa_key_length": rsa_key_length,
                "bb84_eavesdrop_size": sample_size
            },
            "results": {
                "execution_time": f"{execution_time} s",
                "speed": f"{speed} chars/s",
                "memory_before_execution": f"{start_current / 10**6} MB",
                "memory_after_execution": f"{end_current / 10**6} MB",
                "actual_memory_used": f"{actual_memory_used} MB",
                "peak_memory_usage": f"{peak / 10**6} MB"
            }
        }
    except Exception as e:
        progress += 1
        print(f"Running {progress} tests out of {totalTests}")
        return {
            "message": f"Testing message length {len(message)}, key length {rsa_key_length} and sample size {sample_size}",
              "parameters": {
                "message_length": len(message),
                "rsa_key_length": rsa_key_length,
                "bb84_eavesdrop_size": sample_size
            },
            "results": {
                "execution_time": "Failed",
                "speed": "Failed",
                "memory_before_execution": "Failed",
                "memory_after_execution": "Failed",
                "actual_memory_used": "Failed",
                "peak_memory_usage": "Failed"
            }
        }

def generatePerformanceTests(rsa_key_lengths, sample_sizes, messages):
    results = []

    with ThreadPoolExecutor(12) as executor:
        futures = [executor.submit(run_algorithm_test, message, rsa_key_length, sample_size) 
                   for message in messages 
                   for rsa_key_length in rsa_key_lengths 
                   for sample_size in sample_sizes]

        for future in futures:
            results.append(future.result())

    return results