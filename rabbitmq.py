import pika
import json
import logging
import os
import datetime
import threading
import time
import uuid

logger = logging.getLogger(__name__)

class RabbitMQClient:
    def __init__(self):
        """Initialize RabbitMQ client with environment variables"""
        self.host = os.getenv('RABBITMQ_HOST', 'rabbitmq')
        self.port = int(os.getenv('RABBITMQ_PORT', 5672))
        self.username = os.getenv('RABBITMQ_USER', 'guest')
        self.password = os.getenv('RABBITMQ_PASSWORD', 'guest')
        self.vhost = os.getenv('RABBITMQ_VHOST', '/')
        self.connection = None
        self.channel = None
        self.exchange_names = {
            'user_events': 'user_events',
            'order_events': 'order_events',
            'system_events': 'system_events'
        }
        self.consumers = []

    def connect(self):
        """Establish connection to RabbitMQ with retry mechanism"""
        if self.connection is not None and self.connection.is_open:
            return

        retry_count = 0
        max_retries = 5
        
        while retry_count < max_retries:
            try:
                # Create connection parameters
                credentials = pika.PlainCredentials(
                    username=self.username,
                    password=self.password
                )
                
                parameters = pika.ConnectionParameters(
                    host=self.host,
                    port=self.port,
                    virtual_host=self.vhost,
                    credentials=credentials,
                    heartbeat=600,
                    blocked_connection_timeout=300
                )
                
                # Establish connection
                self.connection = pika.BlockingConnection(parameters)
                self.channel = self.connection.channel()
                
                # Declare exchanges
                for exchange_name in self.exchange_names.values():
                    self.channel.exchange_declare(
                        exchange=exchange_name,
                        exchange_type='topic',
                        durable=True
                    )
                
                logger.info(f"Successfully connected to RabbitMQ at {self.host}:{self.port}")
                return
                
            except Exception as e:
                retry_count += 1
                logger.warning(f"Failed to connect to RabbitMQ (attempt {retry_count}/{max_retries}): {str(e)}")
                
                if retry_count >= max_retries:
                    logger.error(f"Maximum retries reached. Could not connect to RabbitMQ: {str(e)}")
                    raise
                
                # Wait before next retry with exponential backoff
                time.sleep(2 ** retry_count)

    def publish_event(self, exchange, routing_key, message):
        """Publish event to specified exchange with routing key"""
        try:
            if self.connection is None or not self.connection.is_open:
                self.connect()
            
            # Add timestamp if not present
            if 'timestamp' not in message:
                message['timestamp'] = datetime.datetime.now().isoformat()
                
            # Add trace_id if not present
            if 'trace_id' not in message:
                message['trace_id'] = str(uuid.uuid4().hex[:8])
            
            # Convert message to JSON
            message_json = json.dumps(message)
            
            # Publish message
            self.channel.basic_publish(
                exchange=self.exchange_names.get(exchange, exchange),
                routing_key=routing_key,
                body=message_json,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                    content_type='application/json'
                )
            )
            
            logger.info(f"Published event to {exchange}.{routing_key}: {message.get('event_type', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to publish event to {exchange}.{routing_key}: {str(e)}")
            
            # Try to reconnect and publish again
            try:
                self.connect()
                
                self.channel.basic_publish(
                    exchange=self.exchange_names.get(exchange, exchange),
                    routing_key=routing_key,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                        content_type='application/json'
                    )
                )
                
                logger.info(f"Successfully republished event to {exchange}.{routing_key} after reconnecting")
                
            except Exception as e2:
                logger.error(f"Failed to republish event after reconnect: {str(e2)}")
                raise

    def start_consumer(self, queue_name, routing_keys, exchange, callback):
        """Start a consumer for the specified queue, binding to routing keys on the exchange"""
        def consumer_thread():
            while True:
                try:
                    if self.connection is None or not self.connection.is_open:
                        self.connect()
                        
                    # Declare the queue
                    self.channel.queue_declare(
                        queue=queue_name,
                        durable=True
                    )
                    
                    # Bind the queue to each routing key
                    for routing_key in routing_keys:
                        self.channel.queue_bind(
                            exchange=self.exchange_names.get(exchange, exchange),
                            queue=queue_name,
                            routing_key=routing_key
                        )
                    
                    def on_message(ch, method, properties, body):
                        try:
                            message = json.loads(body)
                            callback(message)
                            ch.basic_ack(delivery_tag=method.delivery_tag)
                        except Exception as e:
                            logger.error(f"Error processing message: {str(e)}")
                            # Negative acknowledgment to requeue the message
                            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    
                    # Set prefetch count
                    self.channel.basic_qos(prefetch_count=10)
                    
                    # Start consuming
                    self.channel.basic_consume(
                        queue=queue_name,
                        on_message_callback=on_message
                    )
                    
                    logger.info(f"Started consumer for queue '{queue_name}' binding to {routing_keys}")
                    
                    # Start consuming (blocks until channel closed)
                    self.channel.start_consuming()
                    
                except Exception as e:
                    logger.error(f"Consumer error for queue '{queue_name}': {str(e)}")
                    time.sleep(5)  # Wait before reconnecting
        
        # Start consumer in a separate thread
        consumer_thread = threading.Thread(target=consumer_thread)
        consumer_thread.daemon = True
        consumer_thread.start()
        
        # Keep track of consumers
        self.consumers.append(consumer_thread)
        
        return consumer_thread

    def close(self):
        """Close the RabbitMQ connection"""
        if self.connection and self.connection.is_open:
            try:
                self.connection.close()
                logger.info("RabbitMQ connection closed")
            except Exception as e:
                logger.error(f"Error closing RabbitMQ connection: {str(e)}")


# Create a singleton instance
_rabbitmq_client = None

def get_rabbitmq_client():
    """Get or create the RabbitMQ client singleton"""
    global _rabbitmq_client
    if _rabbitmq_client is None:
        _rabbitmq_client = RabbitMQClient()
        _rabbitmq_client.connect()
    return _rabbitmq_client

def publish_event(exchange, routing_key, message):
    """Publish an event to RabbitMQ"""
    client = get_rabbitmq_client()
    client.publish_event(exchange, routing_key, message)

def start_consumer(queue_name, routing_keys, exchange, callback):
    """Start a consumer for the specified queue and routing keys"""
    client = get_rabbitmq_client()
    return client.start_consumer(queue_name, routing_keys, exchange, callback) 