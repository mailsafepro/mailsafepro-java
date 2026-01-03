# Publicar C# SDK en NuGet - Manual

## El problema
La API key de NuGet está rechazando la publicación desde GitHub Actions con error 403.
Esto suele pasar cuando:
- La API key no tiene permisos para crear nuevos paquetes
- O necesita ser usada desde tu máquina primero

## Solución: Publicar manualmente

### Opción 1: Si tienes .NET instalado

```bash
cd sdks/csharp

# 1. Empaquetar
dotnet pack src/MailSafePro/MailSafePro.csproj -c Release

# 2. Publicar
dotnet nuget push src/MailSafePro/bin/Release/MailSafePro.1.0.0.nupkg \
  --api-key $NUGET_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

**IMPORTANTE:** Nunca incluyas tu API Key directamente en el código. Usa variables de entorno:
```bash
export NUGET_API_KEY="tu-api-key-aqui"
```

### Opción 2: Si NO tienes .NET instalado

#### Instalar .NET SDK (Mac):
```bash
brew install --cask dotnet-sdk
```

#### O descarga desde:
https://dotnet.microsoft.com/download

Luego ejecuta los comandos de la Opción 1.

### Opción 3: Usar el script incluido

```bash
cd sdks/csharp
chmod +x publish-to-nuget.sh
./publish-to-nuget.sh
```

## Verificar la publicación

Una vez publicado, verifica en:
- https://www.nuget.org/packages/MailSafePro/

Puede tardar 5-10 minutos en aparecer en los resultados de búsqueda.

## Después de la primera publicación

Una vez que hayas publicado manualmente la primera vez, GitHub Actions debería funcionar para futuras actualizaciones.

## Si sigue fallando

Verifica en NuGet.org que la API key tenga estos permisos:
- ✅ Push new packages and package versions
- ✅ Glob pattern: `MailSafePro*`
