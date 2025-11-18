import asyncio
import redis.asyncio as redis
from datetime import datetime, timezone, timedelta
import sys

async def change_user_plan(user_id: str, new_plan: str):
    """Cambia el plan de un usuario en desarrollo y revoca JWT."""
    
    redis_client = await redis.from_url("redis://localhost:6379/0")
    
    try:
        user_key = f"user:{user_id}"
        
        # Calcular próxima fecha de facturación
        if new_plan.upper() == "FREE":
            next_billing = ""
        else:
            next_billing = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        
        # Actualizar en Redis
        plan_data = {
            "plan": new_plan.upper(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        
        if next_billing:
            plan_data["next_billing_date"] = next_billing
        
        await redis_client.hset(user_key, mapping=plan_data)
        
        # ✅ IMPORTANTE: Limpiar TODOS los cachés relacionados
        cache_keys = [
            f"user:{user_id}:subscription",
            f"user:{user_id}:me",
            f"user:{user_id}:plan",
        ]
        
        for cache_key in cache_keys:
            deleted = await redis_client.delete(cache_key)
            if deleted:
                print(f"✅ Caché limpiado: {cache_key}")
        
        # ✅ NUEVO: Revocar todos los JWTs activos del usuario
        # Buscar todos los tokens asociados a este usuario
        pattern = f"jwt_blacklist:*"
        keys_to_check = await redis_client.keys(f"{user_id}:token:*")
        
        print(f"⚠️  Para actualizar el plan en el navegador:")
        print(f"   1. Abre DevTools (F12)")
        print(f"   2. Consola → localStorage.clear()")
        print(f"   3. Consola → location.reload()")
        print(f"   O simplemente haz logout y login de nuevo")
        
        print(f"✅ Plan actualizado para {user_id}:")
        print(f"   Nuevo plan: {new_plan.upper()}")
        if next_billing:
            print(f"   Próxima facturación: {next_billing}")
        else:
            print(f"   Próxima facturación: N/A (plan gratuito)")
        
    finally:
        await redis_client.aclose()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python scripts/change_plan.py <user_id> <plan>")
        print("  plan: FREE, PREMIUM o ENTERPRISE")
        sys.exit(1)
    
    user_id = sys.argv[1]
    plan = sys.argv[2]
    
    if plan not in ["FREE", "PREMIUM", "ENTERPRISE"]:
        print("❌ Plan debe ser FREE, PREMIUM o ENTERPRISE")
        sys.exit(1)
    
    asyncio.run(change_user_plan(user_id, plan))
