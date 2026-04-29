import traceback
try:
    from torchcrf import CRF
    print('Success: torchcrf imported')
except Exception as e:
    print(f'Error: {type(e).__name__}')
    print(f'Message: {str(e)}')
    traceback.print_exc()
