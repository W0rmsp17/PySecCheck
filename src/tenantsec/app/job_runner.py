from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=4)

def submit_job(fn, *args, **kwargs):
    """Run background work. Returns Future."""
    return _executor.submit(fn, *args, **kwargs)
