from django.apps import AppConfig


class JobAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'jobApp'

    def ready(self):
        try:
            import jobApp.signals
        except ImportError:
            pass