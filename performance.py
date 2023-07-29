import time
import tracemalloc
import json
from r8edsa import R8EDSA

RSA_KEY_LENGTHS = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
SAMPLE_SIZES = [5, 10, 25, 50, 100]
MESSAGES = ["t", "te", "tes", "test"]

def generatePerformanceTests(rsa_key_lengths, sample_sizes, messages):
    results = []

    for message in messages:
        for rsa_key_length in rsa_key_lengths:
            for sample_size in sample_sizes:
                print(f"Testing message length {len(message)}, key length {rsa_key_length} and sample size {sample_size}")
                
                try:
                    
                    # Start tracing memory allocations
                    tracemalloc.start()

                    start_time = time.time()
                    r8edsa = R8EDSA(message, rsa_key_length, sample_size)
                    r8edsa.execute_r8edsa()
                    end_time = time.time()

                    # Stop tracing memory allocations
                    current, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()

                    execution_time = end_time - start_time
                    speed = len(message) / execution_time

                    # Add the result to the list
                    results.append({
                        "message": f"Testing message length {len(message)}, key length {rsa_key_length} and sample size {sample_size}",
                        "parameters": {
                            "message_length": len(message),
                            "rsa_key_length": rsa_key_length,
                            "sample_size": sample_size
                        },
                        "results": {
                            "execution_time": execution_time,
                            "speed": speed,
                            "current_memory_usage": current / 10**6,
                            "peak_memory_usage": peak / 10**6
                        }
                    })
                    print("Test completed successfully!")
                except Exception as e:
                    results.append({
                        "message": f"Testing message length {len(message)}, key length {rsa_key_length} and sample size {sample_size}",
                        "parameters": {
                            "message_length": len(message),
                            "rsa_key_length": rsa_key_length,
                            "sample_size": sample_size
                        },
                        "results": {
                            "execution_time": "Failed",
                            "speed": "Failed",
                            "current_memory_usage": "Failed",
                            "peak_memory_usage": "Failed"
                        }
                    })
                    print("Test failed!")
                    continue

    return results
            


