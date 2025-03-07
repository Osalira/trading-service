from django.apps import AppConfig
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

class TradingAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trading_app'
    verbose_name = "Trading Application"
    
    def ready(self):
        """Initialize components when Django app is ready"""
        # Don't run during Django management commands
        if os.environ.get('RUN_MAIN') != 'true' and 'runserver' not in os.sys.argv:
            return
        
        # Initialize RabbitMQ in a separate thread after app startup
        def init_rabbitmq():
            # Wait for app to fully start
            time.sleep(10)
            try:
                # Import here to avoid circular imports
                from rabbitmq import get_rabbitmq_client, start_consumer
                
                # Initialize RabbitMQ
                client = get_rabbitmq_client()
                logger.info("RabbitMQ client initialized successfully")
                
                # Start consumers for order events and user events
                start_consumer(
                    queue_name='trading_service_order_events',
                    routing_keys=['order.*'],
                    exchange='order_events',
                    callback=self._handle_order_events
                )
                
                start_consumer(
                    queue_name='trading_service_user_events',
                    routing_keys=['user.registered', 'user.deleted'],
                    exchange='user_events',
                    callback=self._handle_user_events
                )
                
                logger.info("RabbitMQ consumers started successfully")
            except Exception as e:
                logger.error(f"Failed to initialize RabbitMQ: {str(e)}")
        
        # Start RabbitMQ initialization in a separate thread
        threading.Thread(target=init_rabbitmq, daemon=True).start()
    
    def _handle_order_events(self, event):
        """Handle order events from RabbitMQ"""
        try:
            logger.info(f"Received order event: {event}")
            event_type = event.get('event_type')
            
            # Process different types of order events
            if event_type == 'order.created':
                logger.info(f"Processing order.created event for order {event.get('order_id')}")
                # You could add business logic here
                
            elif event_type == 'order.updated':
                logger.info(f"Processing order.updated event for order {event.get('order_id')}")
                # You could add business logic here
                
            elif event_type == 'order.completed':
                logger.info(f"Processing order.completed event for order {event.get('order_id')}")
                # You could add business logic here
                
            elif event_type == 'order.cancelled':
                logger.info(f"Processing order.cancelled event for order {event.get('order_id')}")
                # You could add business logic here
        
        except Exception as e:
            logger.error(f"Error processing order event: {str(e)}")
    
    def _handle_user_events(self, event):
        """Handle user events from RabbitMQ"""
        try:
            logger.info(f"Received user event: {event}")
            event_type = event.get('event_type')
            
            # Process user registration events
            if event_type == 'user.registered':
                user_id = event.get('user_id')
                if user_id:
                    logger.info(f"Processing user.registered event for user {user_id}")
                    # You could initialize wallet or portfolio for new users here
                    
            # Process user deletion events
            elif event_type == 'user.deleted':
                user_id = event.get('user_id')
                if user_id:
                    logger.info(f"Processing user.deleted event for user {user_id}")
                    # You could clean up user data here
        
        except Exception as e:
            logger.error(f"Error processing user event: {str(e)}")
