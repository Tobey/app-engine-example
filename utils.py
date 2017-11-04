import json

cache = {}


def simple_cache(f):
    def wrapper(*args, **kwargs):
        cache_key = (f.func_name, args, json.dumps(kwargs))
        if cache_key in cache:
            return cache[cache_key]
        result = f(*args, **kwargs)
        cache[cache_key] = result
        return result
    return wrapper