import pandas as pd
from performance import generatePerformanceTests, RSA_KEY_LENGTHS, SAMPLE_SIZES, MESSAGES

def transform_performance_data(performance_data):
    data_rows = []
    
    for test_result in performance_data:
        parameters = test_result["parameters"]
        results = test_result["results"]
        row = {**parameters, **results}
        data_rows.append(row)
    
    df = pd.DataFrame(data_rows)
    
    return df

print("Exporting a csv file with the performance data...")
df = transform_performance_data(generatePerformanceTests(RSA_KEY_LENGTHS, SAMPLE_SIZES, MESSAGES))
df.to_csv('performance.csv', index=False)
