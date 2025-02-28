from django.apps import AppConfig


class TradingAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trading_app'
    verbose_name = "Trading Application"
    
    def ready(self):
        # Import signals or perform other initialization tasks if needed
        pass
