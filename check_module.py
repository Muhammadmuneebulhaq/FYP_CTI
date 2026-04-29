import importlib.util
try:
    spec = importlib.util.find_spec('torchcrf')
    if spec:
        print(f'torchcrf module found at: {spec.origin}')
    else:
        print('torchcrf module NOT found')
except Exception as e:
    print(f'Error: {e}')
