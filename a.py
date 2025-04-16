from core.config import get_settings

settings = get_settings()

print(settings.SECRET)       # Output from .env
print(settings.ENVIRONMENT)      # dev or prod
print(settings.DEV_DATABASE_URL) # Dev DB URL from .env
