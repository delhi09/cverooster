from config.env.base_settings import *  # NOQA

SECRET_KEY = "2$7!7ts%nhfnvcm+wy$b9s2qca&xjg)l31v43^_m*ox=6&6$n5"

DEBUG = True

ALLOWED_HOSTS = []

if DEBUG:
    INSTALLED_APPS.append("debug_toolbar")  # NOQA
    MIDDLEWARE.append("debug_toolbar.middleware.DebugToolbarMiddleware")  # NOQA
    INSTALLED_APPS.append("silk")  # NOQA
    MIDDLEWARE.append("silk.middleware.SilkyMiddleware")  # NOQA

    def show_toolbar(request):
        return True

    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": show_toolbar,
    }

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "cve",
        "USER": "root",
        "PASSWORD": "password",
        "HOST": "127.0.0.1",
        "PORT": "3306",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379",
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient",},
    }
}
