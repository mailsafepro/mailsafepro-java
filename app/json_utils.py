"""
JSON serialization utilities using orjson for performance.

orjson is 2-3x faster than standard library json and handles:
- datetime objects
- UUID objects
- dataclasses
- numpy arrays (if available)
"""

import orjson
from typing import Any, Dict

def dumps(obj: Any) -> str:
    """
    Serialize obj to JSON string using orjson (2-3x faster than json.dumps).
    
    Returns:
        JSON string (decoded from bytes)
    """
    return orjson.dumps(
        obj,
        option=orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY
    ).decode('utf-8')

def loads(s: str | bytes) -> Any:
    """
    Deserialize JSON string/bytes to Python object using orjson.
    
    Args:
        s: JSON string or bytes
    
    Returns:
        Deserialized Python object
    """
    if isinstance(s, str):
        s = s.encode('utf-8')
    return orjson.loads(s)

def dumps_bytes(obj: Any) -> bytes:
    """
    Serialize obj to JSON bytes using orjson (for Redis, msgpack, etc).
    
    Returns:
        JSON bytes
    """
    return orjson.dumps(
        obj,
        option=orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY
    )
