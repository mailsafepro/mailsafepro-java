import hashlib
import redis
from app.config import settings
from app.api_keys import generate_api_key  # tu función de generación de claves

# Conecta a Redis
r = redis.Redis.from_url(str(settings.redis_url), decode_responses=True)

def list_active_api_keys():
    keys = r.keys("key:*")
    result = []
    for k in keys:
        # k tiene formato: key:<sha256_hash>
        sha_hash = k.split(":")[1]

        # ⚠️ Esto **NO puede revertirse**, SHA256 es unidireccional.
        # Para testing: generamos nuevas claves y vemos cuál coincide con este hash
        # Ejemplo: generar 10 claves temporales y comparar hashes
        for _ in range(1000):
            candidate = generate_api_key()  # Devuelve texto plano
            candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
            if candidate_hash == sha_hash:
                result.append((candidate, k))
                break
    return result

if __name__ == "__main__":
    active = list_active_api_keys()
    for plain, redis_key in active:
        print(f"Redis key: {redis_key} | Plaintext key: {plain}")