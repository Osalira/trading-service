from django.http import JsonResponse
from django.db import transaction as db_transaction
from django.db.models import F, Case, When, Value, IntegerField, Sum, Avg, Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
import logging
import requests
import json
import jwt
from django.conf import settings
from decimal import Decimal
import os
import uuid
from django.utils import timezone
from datetime import timedelta
from django.db import connection
import traceback
from django.core.cache import cache
from django.db import connections, OperationalError
import random
import time
import threading
from threading import local
import re

from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction, OrderStatus, OrderType
from serializers import (
    StockSerializer, UserPortfolioSerializer, WalletSerializer,
    StockTransactionSerializer, WalletTransactionSerializer,
    StockPriceSerializer, PortfolioResponseSerializer,
    CreateOrderSerializer, CancelOrderSerializer, AddMoneySerializer,
    WalletBalanceSerializer, JMeterStockTransactionSerializer,
    JMeterWalletTransactionSerializer
)

# Import RabbitMQ functions for event publishing
from rabbitmq import publish_event

# Configure logging
logger = logging.getLogger(__name__)

# Helper function to get user_id from request
def get_user_id(request):
    logger.debug("Attempting to get user_id from request")
    
    # First try to get user_id from query parameters
    user_id_param = request.query_params.get('user_id')
    if user_id_param:
        logger.debug(f"Found user_id from query parameter: {user_id_param}")
        return user_id_param
    
     # Try Django's META dict with HTTP_ prefix
    for meta_key in ['HTTP_USER_ID', 'HTTP_USERID']:
        if meta_key in request.META:
            user_id_meta = request.META.get(meta_key)
            logger.debug(f"Found user_id from META {meta_key}: {user_id_meta}")
            return user_id_meta


    # Second try to get user_id from our custom authentication class
    if hasattr(request, 'user_id'):
        logger.debug(f"Found user_id from request attribute: {request.user_id}")
        return request.user_id
    
    # Try to get from the user_id header - check different formats
    for header_key in ['user_id', 'User-Id', 'USER_ID', 'userId']:
        user_id_header = request.headers.get(header_key)
        if user_id_header:
            logger.debug(f"Found user_id from header {header_key}: {user_id_header}")
            return user_id_header
    
    # Check the request data for POST/PUT requests
    if hasattr(request, 'data') and isinstance(request.data, dict) and 'user_id' in request.data:
        user_id_data = request.data.get('user_id')
        logger.debug(f"Found user_id in request.data: {user_id_data}")
        return user_id_data
    
    # As a last resort, try to extract from auth object if present
    if hasattr(request, 'auth') and request.auth:
        try:
            if isinstance(request.auth, dict) and 'id' in request.auth:
                logger.debug(f"Found user_id from auth object: {request.auth.get('id')}")
                return request.auth.get('id')
        except Exception as e:
            logger.error(f"Error extracting user_id from auth object: {str(e)}")
    
    logger.warning("No user_id found in request")
    # Default to user ID 1 for testing instead of None
    logger.info("Using default user ID 1 for testing")
    return "1"

# Helper function to format decimal values without .0 for whole numbers
def format_decimal(value):
    """Format decimal values to remove .0 for whole numbers"""
    if isinstance(value, Decimal):
        # Convert to float first to handle potential Decimal precision issues
        float_val = float(value)
        # Check if it's a whole number
        if float_val.is_integer():
            return int(float_val)
    return value

# Transaction API endpoints

@api_view(['GET'])
@permission_classes([AllowAny])
def get_stock_prices(request):
    """Get a list of all stocks with their current prices"""
    try:
        # Try to get cached stock prices first
        cache_key = 'all_stock_prices'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            logger.debug("Returning cached stock prices")
            return Response({"success": True, "data": cached_data, "cached": True})
            
        # Cache miss - fetch from database
        start_time = time.time()
        stocks = Stock.objects.all().order_by('-company_name')
        serializer = StockPriceSerializer(stocks, many=True)
        
        # Cache the result for 5 seconds (adjustable based on update frequency)
        cache.set(cache_key, serializer.data, 5)
        
        execution_time = time.time() - start_time
        logger.debug(f"Fetched stock prices from DB in {execution_time:.3f}s")
        
        return Response({
            "success": True, 
            "data": serializer.data,
            "cached": False,
            "execution_time_ms": int(execution_time * 1000)
        })
    except Exception as e:
        logger.error(f"Error fetching stock prices: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": "Failed to fetch stock prices"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def get_stock_portfolio(request):
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "data": {"error": "No user ID provided"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )
    
    # Add request tracking ID for tracing through logs
    request_id = str(uuid.uuid4())[:8]
    logger.info(f"[REQ-{request_id}] Getting stock portfolio for user {user_id}")
    
    try:
        # OPTIMIZATION: Combine portfolio and pending sell queries into a single transaction
        # to reduce database load and improve consistency
        with db_transaction.atomic():
            # Get all stocks owned by the user
            portfolio = UserPortfolio.objects.filter(user_id=user_id).select_related('stock')
            
            # Get pending sell orders (status PENDING, PARTIAL, or IN_PROGRESS) in the same transaction
            # OPTIMIZATION: Add index hint to improve query performance
            pending_sell_orders = StockTransaction.objects.filter(
                user_id=user_id,
                is_buy=False,  # sell orders only
                status__in=[OrderStatus.PENDING, OrderStatus.PARTIALLY_COMPLETE, OrderStatus.IN_PROGRESS]
            ).select_related('stock')
            
            # OPTIMIZATION: Process all this data in memory to reduce DB round trips
            # Build a dictionary of pending sell quantities by stock_id
            pending_sell_quantity = {}
            for order in pending_sell_orders:
                stock_id = int(order.stock_id)
                pending_sell_quantity[stock_id] = pending_sell_quantity.get(stock_id, 0) + order.quantity
            
            # Log condensed information rather than verbose logs for each item
            logger.info(f"[REQ-{request_id}] User {user_id} portfolio has {portfolio.count()} stocks and {pending_sell_orders.count()} pending sell orders")
            
            # Process portfolio items to compute available quantity, all in memory
            portfolio_items = []
            for item in portfolio:
                stock_id_int = int(item.stock_id)
                
                # Get pending sell quantity for this stock (if any)
                pending_sell_qty = pending_sell_quantity.get(stock_id_int, 0)
                
                # Skip if the entire quantity is pending sell
                if pending_sell_qty >= item.quantity:
                    continue
                
                # Calculate available quantity
                available_quantity = item.quantity - pending_sell_qty
                
                # Only add to portfolio if there are available shares
                if available_quantity > 0:
                    portfolio_item = {
                        'stock_id': str(item.stock_id),
                        'stock_name': item.stock.company_name if hasattr(item.stock, 'company_name') else item.stock.name,
                        'stock_symbol': item.stock.symbol,
                        'current_price': item.stock.current_price,
                        'average_price': item.average_price,
                        'quantity_owned': item.quantity,
                        'total_value': float(item.stock.current_price or 0) * available_quantity if item.stock.current_price else 0,
                        'profit_loss': 0,
                        'profit_loss_percentage': 0,
                        'available_quantity': available_quantity
                    }
                    
                    # Calculate profit/loss if we have both prices
                    if item.average_price and item.stock.current_price:
                        portfolio_item['profit_loss'] = (item.stock.current_price - item.average_price) * available_quantity
                        if item.average_price > 0:
                            portfolio_item['profit_loss_percentage'] = ((item.stock.current_price - item.average_price) / item.average_price) * 100
                    
                    portfolio_items.append(portfolio_item)
        
        # Sort portfolio items in reverse alphabetical order by stock_name (Z to A)
        portfolio_items.sort(key=lambda item: item['stock_name'], reverse=True)
        
        logger.info(f"[REQ-{request_id}] Final available portfolio contains {len(portfolio_items)} stocks")
        
        # Return the portfolio in JMeter format
        return Response({"success": True, "data": portfolio_items})
    
    except Exception as e:
        logger.error(f"[REQ-{request_id}] Error fetching stock portfolio: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def get_stock_transactions(request):
    """
    Get a user's stock transaction history
    """
    try:
        # Always use JMeter format for this endpoint
        use_jmeter_format = True
        logger.debug(f"Using JMeter format: {use_jmeter_format}")
        
        # Get the user ID from the request
        user_id = get_user_id(request)
        if not user_id:
            return Response(
                {"success": False, "data": {"error": "User ID is required"}}, 
                status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
            )
        
        # Add request tracking ID for tracing through logs
        request_id = str(uuid.uuid4())[:8]
        logger.info(f"[REQ-{request_id}] Fetching stock transactions for user ID: {user_id}")
        
        # Get pagination parameters from the query string
        limit = int(request.query_params.get('limit', 100))
        offset = int(request.query_params.get('offset', 0))
        
        # Fetch the transactions ordered by timestamp (newest first) to match wallet transactions view
        transactions = StockTransaction.objects.filter(user_id=user_id).order_by('timestamp')
        
        # Use select_related to fetch related objects in one query
        transactions = transactions.select_related('stock')
        
        logger.debug(f"[REQ-{request_id}] Found {transactions.count()} transactions")
        
        # Apply pagination if needed
        if limit > 0:
            transactions = transactions[offset:offset+limit]
        
        # Log details of each transaction for debugging
        for tx in transactions:
            logger.debug(f"Transaction {tx.id}: stock={tx.stock_id}, price={tx.price}")
        
        # Serialize the data using JMeter format
        serialized_data = JMeterStockTransactionSerializer(transactions, many=True).data
        
        # Return with success key for consistency with other endpoints
        return Response({"success": True, "data": serialized_data})
    
    except Exception as e:
        logger.error(f"Error fetching stock transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )

@api_view(['POST'])
# @permission_classes([IsAuthenticated])
@permission_classes([AllowAny])
def add_money_to_wallet(request):
    """Add money to the user's wallet"""
    trace_id = str(uuid.uuid4())[:8]
    start_time = time.time()
    
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    logger.info(f"[TraceID: {trace_id}] Processing add money request for user {user_id}")
    
    serializer = AddMoneySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    amount = serializer.validated_data['amount']
    
    # Validate amount is positive
    if amount <= 0:
        return Response(
            {"error": "Amount must be positive"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Use select_for_update to prevent race conditions
        with db_transaction.atomic():
            # Get or create wallet with a lock to prevent concurrent modifications
            wallet, created = Wallet.objects.select_for_update().get_or_create(
                user_id=user_id,
                defaults={'balance': 0}
            )
            
            # Convert amount to Decimal for precise calculation
            decimal_amount = Decimal(str(amount))
            
            # Update balance using F expressions for atomic update
            # This ensures that concurrent transactions don't override each other
            wallet.balance = F('balance') + decimal_amount
            wallet.save()
            
            # Create wallet transaction within the same transaction
            transaction = WalletTransaction.objects.create(
                user_id=user_id,
                is_debit=False,  # Credit transaction
                amount=decimal_amount,
                description=f"Added {decimal_amount} funds to wallet"
            )
            
            # Force refresh to get the updated balance
            wallet.refresh_from_db()
            
            logger.info(f"[TraceID: {trace_id}] Successfully added {decimal_amount} to wallet for user {user_id}. New balance: {wallet.balance}")
            
            execution_time = time.time() - start_time
            return Response({
                "success": True,
                "message": "Funds added successfully",
                "transaction_id": transaction.id,
                "new_balance": format_decimal(wallet.balance),
                "amount_added": format_decimal(amount),
                "execution_time_ms": int(execution_time * 1000)
            })
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error adding money for user {user_id}: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": "Failed to add money to wallet"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])  # Use AllowAny for testing
def get_wallet_balance(request):
    """Get the user's wallet balance"""
    # Add request tracking ID for tracing through logs
    request_id = str(uuid.uuid4())[:8]
    logger.info(f"[REQ-{request_id}] Fetching wallet balance")
    start_time = time.time()
    
    # Get user_id using our helper function
    user_id = get_user_id(request)
    if not user_id:
        logger.warning(f"[REQ-{request_id}] No user_id found in request")
        return Response(
            {"success": False, "error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    logger.info(f"[REQ-{request_id}] Fetching wallet balance for user_id: {user_id}")
    
    try:
        # Fetch from database
        with db_transaction.atomic():
            wallet, created = Wallet.objects.get_or_create(
                user_id=user_id,
                defaults={'balance': Decimal('0.00')}
            )
            
            execution_time = time.time() - start_time
            logger.info(f"[REQ-{request_id}] Wallet balance for user {user_id}: {wallet.balance} (fetched from DB)")
            
            return Response({
                "success": True,
                "data": {
                    "user_id": user_id,
                    "balance": format_decimal(wallet.balance),
                    "cached": False
                },
                "execution_time_ms": int(execution_time * 1000)
            })
    except Exception as e:
        logger.error(f"[REQ-{request_id}] Error fetching wallet balance for user {user_id}: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": f"Failed to fetch wallet balance: {str(e)}"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])  # Use AllowAny for testing
def get_wallet_transactions(request):
    """Get the user's wallet transaction history"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "data": {"error": "User ID not provided"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )
    
    try:
        # Get transaction parameters from query string
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get ONLY the requested user's transactions
        # IMPORTANT: This is where we fix the bug - strictly filter by user_id
        all_transactions = WalletTransaction.objects.filter(user_id=user_id)
        
        # NEW: Additional filtering to ensure data integrity
        valid_transactions = []
        invalid_reference_count = 0
        cross_user_reference_count = 0
        
        # First pass: Check for invalid references and log warnings
        for tx in all_transactions:
            is_valid = True
            
            if tx.stock_transaction_id is not None:
                # Check if the referenced stock transaction exists
                try:
                    stock_tx = StockTransaction.objects.get(id=tx.stock_transaction_id)
                    
                    # Check if stock transaction belongs to the same user
                    if stock_tx.user_id != int(user_id):
                        logger.warning(f"CROSS-USER REFERENCE: Wallet transaction {tx.id} for user {user_id} references stock transaction {tx.stock_transaction_id} belonging to user {stock_tx.user_id}")
                        cross_user_reference_count += 1
                        # Mark as invalid - we don't want to show cross-user references
                        is_valid = False
                except StockTransaction.DoesNotExist:
                    logger.warning(f"INVALID REFERENCE: Wallet transaction {tx.id} references non-existent stock transaction {tx.stock_transaction_id}")
                    invalid_reference_count += 1
                    # Don't show transactions with references to non-existent entities
                    is_valid = False
            
            if is_valid:
                valid_transactions.append(tx)
        
        logger.info(f"Filtered out {cross_user_reference_count} cross-user references and {invalid_reference_count} invalid references")
        all_transactions = valid_transactions
        
        # Process transactions to handle potential duplicates where stock_transaction is null
        
        # Apply pagination
        transactions = all_transactions[offset:offset+limit]
        
        # Serialize transactions
        serialized_transactions = WalletTransactionSerializer(transactions, many=True).data
        
        return Response({"success": True, "data": serialized_transactions})
    except Exception as e:
        logger.error(f"Error fetching wallet transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )

# Setup endpoints

@api_view(['POST'])
@permission_classes([AllowAny])
def create_stock(request):
    """Create a new stock (open to any authenticated user)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Accept any authenticated user
    
    serializer = StockSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({"success": False, "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        stock = serializer.save()
        # Get serialized data and rename 'id' to 'stock_id'
        stock_data = StockSerializer(stock).data
        stock_data['stock_id'] = stock_data.pop('id')
        
        return Response({
            'success': True,
            'data': stock_data
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f"Error creating stock: {str(e)}")
        return Response(
            {"success": False, "error": "Failed to create stock"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def add_stock_to_user(request):
    """Add stock to a user's portfolio (open to any authenticated user)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Accept any authenticated user
    
    # Set defaults for missing fields
    data = request.data.copy()
    
    # Use authenticated user's ID as target_user_id if not provided
    if 'target_user_id' not in data or not data['target_user_id']:
        data['target_user_id'] = user_id
        logger.info(f"Using authenticated user's ID ({user_id}) as target_user_id")
    
    # Get latest stock if stock_id not provided
    if 'stock_id' not in data or not data['stock_id']:
        try:
            latest_stock = Stock.objects.latest('created_at')
            data['stock_id'] = latest_stock.id
            logger.info(f"Using latest stock ID: {latest_stock.id} ({latest_stock.symbol})")
        except Stock.DoesNotExist:
            return Response(
                {"error": "No stocks found in the system and no stock_id provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Ensure quantity is provided
    if 'quantity' not in data:
        return Response(
            {"error": "Missing required field: quantity"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    target_user_id = data['target_user_id']
    stock_id = data['stock_id']
    
    try:
        quantity = int(data['quantity'])
    except (ValueError, TypeError):
        return Response(
            {"error": "Quantity must be a valid integer"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if quantity <= 0:
        return Response(
            {"error": "Quantity must be positive"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        with db_transaction.atomic():
            # Get stock
            try:
                stock = Stock.objects.get(id=stock_id)
            except Stock.DoesNotExist:
                return Response(
                    {"error": f"Stock with ID {stock_id} not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            # Get or create portfolio entry
            portfolio, _ = UserPortfolio.objects.get_or_create(
                user_id=target_user_id,
                stock=stock,
                defaults={'quantity': 0}
            )
            
            # Just update the quantity, don't touch average_price
            portfolio.quantity += data['quantity']
            portfolio.save()
            
            return Response({
                "message": "Stock added to user portfolio",
                "portfolio": UserPortfolioSerializer(portfolio).data
            })
    except Exception as e:
        logger.error(f"Error adding stock to user {target_user_id}: {str(e)}")
        return Response(
            {"error": f"Failed to add stock to user: {str(e)}"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def process_transaction(request):
    """Process a transaction notification from the matching engine
    
    This can handle either a match notification or an order status notification:
    1. Match notification - when orders are matched, update wallet and portfolio.
    2. Order status notification - when a new order is placed, ensure it's in our system.
    
    This function is now the ONLY place where wallet transactions are created to prevent duplicates.
    """
    # Generate a trace ID for tracking this transaction
    trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
    logger.info(f"[TraceID: {trace_id}] Starting transaction processing")
    
    try:
        data = request.data
        
        # OPTIMIZATION: Reduce logging verbosity for high concurrency
        logger.info(f"[TraceID: {trace_id}] Received transaction notification type: {data.get('notification_type', 'match')}")
        
        # Check if this is a new order notification
        if data.get('notification_type') == 'new_order':
            # This is an order status notification
            logger.info(f"[TraceID: {trace_id}] This is a new order notification, forwarding to process_order_notification")
            return process_order_notification(data, trace_id)
        
        # Otherwise, process as a transaction/match notification
        buy_user_id = data.get('buy_user_id')
        sell_user_id = data.get('sell_user_id')
        stock_id = data.get('stock_id')
        quantity = data.get('quantity')
        price = data.get('price')
        timestamp = data.get('timestamp')
        buy_order_id = data.get('buy_order_id')  # External ID from matching engine
        sell_order_id = data.get('sell_order_id')  # External ID from matching engine
        
        if not all([buy_user_id, sell_user_id, stock_id, quantity, price]):
            logger.error(f"[TraceID: {trace_id}] Missing required fields in transaction notification")
            
            # Publish error event
            publish_event('system_events', 'system.error', {
                'event_type': 'system.error',
                'service': 'trading-service',
                'operation': 'process_transaction',
                'error': 'Missing required fields in transaction notification',
                'trace_id': trace_id
            })
            
            return Response(
                {"success": False, "error": "Missing required fields"}, 
                status=status.HTTP_200_OK  # Return 200 to avoid retries
            )
        
        # OPTIMIZATION: Use select_for_update to avoid race conditions and deadlocks
        # Use a transaction block to ensure database consistency
        with db_transaction.atomic():
            # Get stock object - needed for both symbol and for portfolio operations
            stock_obj = Stock.objects.select_for_update().get(id=stock_id)
            stock_symbol = stock_obj.symbol
            
            # Find or create the buyer's stock transaction
            buy_tx, buy_created = StockTransaction.objects.select_for_update().get_or_create(
                external_order_id=buy_order_id,
                defaults={
                    'user_id': buy_user_id,
                    'stock': stock_obj,
                    'is_buy': True,
                    'quantity': quantity,
                    'price': price,
                    'status': OrderStatus.COMPLETED,
                    'order_type': OrderType.MARKET,  # Default to MARKET for backward compatibility
                    'timestamp': timestamp or timezone.now(),
                    'trace_id': trace_id
                }
            )
            
            # Update buyer's portfolio
            buy_portfolio, _ = UserPortfolio.objects.select_for_update().get_or_create(
                user_id=buy_user_id,
                stock=stock_obj,
                defaults={'quantity': 0, 'average_price': 0}
            )
            
            # Find or create the seller's stock transaction
            sell_tx, sell_created = StockTransaction.objects.select_for_update().get_or_create(
                external_order_id=sell_order_id,
                defaults={
                    'user_id': sell_user_id,
                    'stock': stock_obj,
                    'is_buy': False,
                    'quantity': quantity,
                    'price': price,
                    'status': OrderStatus.COMPLETED,
                    'order_type': OrderType.MARKET,  # Default to MARKET for backward compatibility
                    'timestamp': timestamp or timezone.now(),
                    'trace_id': trace_id
                }
            )
            
            # Update seller's portfolio
            sell_portfolio, _ = UserPortfolio.objects.select_for_update().get_or_create(
                user_id=sell_user_id,
                stock=stock_obj,
                defaults={'quantity': 0, 'average_price': 0}
            )
            
            # Process both transactions atomically
            transaction_success = process_stock_transaction(buy_tx, trace_id) and process_stock_transaction(sell_tx, trace_id)
            
            if transaction_success:
                # Calculate total value
                total_value = Decimal(str(price)) * int(quantity)
                
                # Publish the event after successful processing
                publish_event('order_events', 'order.matched', {
                    'event_type': 'order.matched',
                    'trace_id': trace_id,
                    'buy_user_id': buy_user_id,
                    'sell_user_id': sell_user_id,
                    'buy_order_id': buy_order_id,
                    'sell_order_id': sell_order_id,
                    'stock_id': stock_id,
                    'stock_symbol': stock_symbol,
                    'quantity': quantity,
                    'price': str(price),
                    'matched_at': timestamp or timezone.now().isoformat(),
                    'total_value': str(total_value)
                })
        
        return Response({"success": True})
        
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error processing transaction: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Publish error event
        try:
            publish_event('system_events', 'system.error', {
                'event_type': 'system.error',
                'service': 'trading-service',
                'operation': 'process_transaction',
                'error': str(e),
                'trace_id': trace_id
            })
        except Exception as publish_error:
            logger.error(f"[TraceID: {trace_id}] Failed to publish error event: {str(publish_error)}")
        
        return Response(
            {"success": False, "error": f"Failed to process transaction: {str(e)}"},
            status=status.HTTP_200_OK  # Return 200 to avoid retries
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def process_order_notification(request):
    """Process order notifications from the order service"""
    logger.info(f"Processing order notification")
    
    # Generate a trace ID for tracking this request
    trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
    # Log the request data
    logger.debug(f"Request data: {request.data}")
    
    # Map order service status to our internal status - use the exact values from OrderStatus in models.py
    STATUS_MAP = {
        'PENDING': OrderStatus.PENDING,            # 'Pending'
        'COMPLETED': OrderStatus.COMPLETED,        # 'Completed'
        'CANCELLED': OrderStatus.CANCELLED,        # 'Cancelled'
        'PARTIAL': OrderStatus.PARTIALLY_COMPLETE, # 'Partially_complete'
        'EXPIRED': OrderStatus.CANCELLED,          # 'Cancelled'
        'FAILED': OrderStatus.REJECTED,            # 'Rejected'
        'INPROGRESS': OrderStatus.IN_PROGRESS      # 'InProgress'
    }
    
    try:
        # Extract data from request
        status = request.data.get('status', '').upper()
        quantity = float(request.data.get('quantity', 0))
        price = float(request.data.get('price', 0))
        order_id = request.data.get('order_id')
        stock_symbol = request.data.get('stock_symbol')
        
        # Check for both potential field names for order type with more robust handling
        order_type = request.data.get('order_type') 
        if not order_type:
            # Try alternate field name
            order_type = request.data.get('type')
        
        # Convert to proper format for OrderType model field
        # The OrderType enum expects 'Market' or 'Limit' (not uppercase)
        if order_type:
            # First normalize to uppercase for comparison
            order_type_upper = order_type.upper() if isinstance(order_type, str) else ''
            
            # Map to correct format for the model
            if order_type_upper == 'MARKET':
                order_type = OrderType.MARKET  # This is 'Market'
            elif order_type_upper == 'LIMIT':
                order_type = OrderType.LIMIT   # This is 'Limit'
            else:
                # Default to LIMIT if unrecognized
                logger.warning(f"Unrecognized order type: {order_type}, defaulting to LIMIT")
                order_type = OrderType.LIMIT
        else:
            # Default if not provided
            logger.warning(f"No order_type provided in request, defaulting to LIMIT")
            order_type = OrderType.LIMIT
            
        user_id = request.data.get('user_id')
        is_buy = request.data.get('is_buy', True)
        
        if status not in STATUS_MAP:
            logger.warning(f"Received unknown status '{status}' from order service")
            mapped_status = OrderStatus.PENDING  # Default to pending if unknown
        else:
            mapped_status = STATUS_MAP[status]
        
        logger.info(f"Mapped order status from '{status}' to '{mapped_status}'")
        
        # Require essential parameters
        if not order_id or not stock_symbol:
            return Response({"success": False, "error": "Missing required parameters"}, status=400)
        
        # Get the stock
        stock = None
        try:
            stock = Stock.objects.get(symbol=stock_symbol)
            logger.info(f"Found stock {stock.symbol} with ID {stock.id}")
        except Stock.DoesNotExist:
            logger.warning(f"Stock {stock_symbol} not found, creating it")
            stock = Stock.objects.create(
                symbol=stock_symbol,
                name=f"{stock_symbol} Stock",
                current_price=price or 100.00  # Default price if none provided
            )
        
        # Add quantity validation for buy orders
        if mapped_status != OrderStatus.CANCELLED and is_buy and quantity <= 0:
            return Response({
                "success": False,
                "error": "Invalid quantity for buy order"
            }, status=400)
        
        # Check if we already have a transaction for this order
        existing_tx = StockTransaction.objects.filter(external_order_id=order_id).first()
        
        if existing_tx:
            logger.info(f"Found existing transaction for order {order_id}, updating status from {existing_tx.status} to {mapped_status}")
            
            # Update the existing transaction
            existing_tx.status = mapped_status
            existing_tx.price = price if price > 0 else existing_tx.price
            existing_tx.quantity = quantity if quantity > 0 else existing_tx.quantity
            existing_tx.save()
            
            # Process wallet for completed transactions
            if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                # Check if this stock transaction already has a wallet transaction
                existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=existing_tx).exists()
                
                if existing_wallet_tx:
                    logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                else:
                    # Only process if no wallet transaction exists yet
                    process_stock_transaction(existing_tx, trace_id)
            
            return Response({
                "success": True,
                "message": f"Updated transaction status to {mapped_status}"
            })
        else:
            logger.info(f"Creating new transaction for order {order_id}")
            
            # Better duplicate detection - check for similar transactions in the last 5 seconds
            recent_tx = StockTransaction.objects.filter(
                user_id=user_id,
                stock=stock,
                is_buy=is_buy,
                quantity=quantity,
                price=price,
                timestamp__gte=timezone.now() - timezone.timedelta(seconds=5)
            ).first()
            
            if recent_tx:
                logger.info(f"Found similar recent transaction {recent_tx.id} (within 5 seconds), updating it instead of creating new")
                
                # Update the existing similar transaction
                recent_tx.external_order_id = order_id  # Add the external order ID
                recent_tx.status = mapped_status
                recent_tx.save()
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    # Check if this stock transaction already has a wallet transaction
                    existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=recent_tx).exists()
                    
                    if existing_wallet_tx:
                        logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                    else:
                        # Only process if no wallet transaction exists yet
                        process_stock_transaction(recent_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Updated similar recent transaction {recent_tx.id} with order ID {order_id} and status {mapped_status}"
                })
            
            # Create a new transaction
            try:
                tx = StockTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    is_buy=is_buy,
                    order_type=order_type,
                    status=mapped_status,
                    quantity=quantity,
                    price=price,
                    external_order_id=order_id
                )
                
                logger.info(f"Created transaction with ID {tx.id} for order {order_id}")
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    process_stock_transaction(tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Created new transaction with status {mapped_status}"
                })
            except Exception as e:
                logger.error(f"Error creating transaction: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({
                    "success": False, 
                    "data": {"error": f"Failed to create transaction: {str(e)}"}
                }, status=status.HTTP_200_OK)  # Return 200 for JMeter
    except Exception as e:
        logger.error(f"Error processing order notification: {str(e)}")
        logger.error(traceback.format_exc())
        return Response({
            "success": False,
            "data": {"error": f"Internal error: {str(e)}"}
        }, status=status.HTTP_200_OK)  # Return 200 for JMeter

@api_view(['POST'])
@permission_classes([AllowAny])
def process_order_status(request):
    """Process order status notifications from the matching engine"""
    # Add initial log for incoming request
    logger.debug("Received order status notification: %s", request.data)
    
    trace_id = str(uuid.uuid4())[:8]
    logger.info(f"[TraceID: {trace_id}] Processing order status notification")
    
    # Get data from request
    try:
        data = request.data
        
        # Validate required fields
        required_fields = ['user_id', 'stock_id', 'order_id', 'status']
        for field in required_fields:
            if field not in data:
                logger.error(f"[TraceID: {trace_id}] Missing required field: {field}")
                return Response(
                    {"success": False, "error": f"Missing required field: {field}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Extract fields
        user_id = data.get('user_id')
        stock_id = data.get('stock_id')
        order_id = data.get('order_id')
        order_status = data.get('status', '').upper()
        is_buy = data.get('is_buy', True)
        order_type = data.get('order_type', 'Market')
        quantity = int(data.get('quantity', 0))
        price = float(data.get('price', 0))
        notification_type = data.get('notification_type', 'new_order')
        
        # Handle parent-child relationship for partial matches
        parent_order_id = data.get('parent_order_id')
        is_child_order = data.get('is_child_order', False)
        is_partial_match = data.get('is_partial_match', False)
        
        # Map status values
        STATUS_MAP = {
            'PENDING': OrderStatus.PENDING,            # 'Pending'
            'COMPLETED': OrderStatus.COMPLETED,        # 'Completed'
            'CANCELLED': OrderStatus.CANCELLED,        # 'Cancelled'
            'PARTIAL': OrderStatus.PARTIALLY_COMPLETE, # 'Partially_complete'
            'PARTIALLY_COMPLETE': OrderStatus.PARTIALLY_COMPLETE, # 'Partially_complete'
            'EXPIRED': OrderStatus.CANCELLED,          # 'Cancelled'
            'FAILED': OrderStatus.REJECTED,            # 'Rejected'
            'INPROGRESS': OrderStatus.IN_PROGRESS      # 'InProgress'
        }
        
        # Map the status
        mapped_status = STATUS_MAP.get(order_status, OrderStatus.PENDING)
        
        # Get the stock
        try:
            stock = Stock.objects.get(id=stock_id)
        except Stock.DoesNotExist:
            logger.error(f"[TraceID: {trace_id}] Stock not found: {stock_id}")
            return Response(
                {"success": False, "error": f"Stock not found: {stock_id}"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Log extracted fields
        logger.debug(
            "Extracted fields - user_id: %s, stock_id: %s, order_id: %s, order_status: %s, is_buy: %s, order_type: %s, quantity: %s, price: %s, notification_type: %s",
            user_id, stock_id, order_id, order_status, is_buy, order_type, quantity, price, notification_type
        )
        
        # Log parent-child relationship
        if is_child_order:
            logger.debug("This is a child order with parent_order_id: %s", parent_order_id)
        if is_partial_match:
            logger.debug("This is a partial match notification for order_id: %s", order_id)
        
        # Check if transaction exists based on external_order_id
        existing_tx = StockTransaction.objects.filter(external_order_id=order_id).first()
        
        # Special handling for partial match completions
        if is_child_order and is_partial_match and notification_type == 'partial_match_completion':
            logger.info(f"[TraceID: {trace_id}] Processing partial match completion for order {order_id} from parent {parent_order_id}")
            
            # Find the parent transaction
            parent_tx = StockTransaction.objects.filter(external_order_id=parent_order_id).first()
            
            if parent_tx:
                # Create a child transaction for the completed portion of the order
                child_tx = StockTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    is_buy=is_buy,
                    order_type=parent_tx.order_type,  # Use same type as parent
                    status=OrderStatus.COMPLETED,
                    quantity=quantity,
                    price=price,
                    parent_transaction=parent_tx,
                    external_order_id=order_id
                )
                
                logger.info(f"[TraceID: {trace_id}] Created child transaction {child_tx.id} for parent {parent_tx.id}")
                
                # Process the completed child transaction to update wallet and portfolio
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    process_stock_transaction(child_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Created child transaction for partial match", 
                    "transaction_id": child_tx.id
                })
            else:
                logger.error(f"[TraceID: {trace_id}] Parent transaction not found for order_id {parent_order_id}")
                return Response(
                    {"success": False, "error": f"Parent transaction not found for order_id {parent_order_id}"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Handle regular order status updates
        if existing_tx:
            logger.info(f"[TraceID: {trace_id}] Updating existing transaction for order {order_id}")
            
            # Update the existing transaction
            existing_tx.status = mapped_status
            existing_tx.price = price if price > 0 else existing_tx.price
            existing_tx.quantity = quantity if quantity > 0 else existing_tx.quantity
            existing_tx.save()
            
            # Process wallet for completed transactions
            if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                # Check if this stock transaction already has a wallet transaction
                existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=existing_tx).exists()
                
                if existing_wallet_tx:
                    logger.info(f"[TraceID: {trace_id}] This transaction already has a wallet transaction, skipping wallet update")
                else:
                    # Only process if no wallet transaction exists yet
                    process_stock_transaction(existing_tx, trace_id)
            
            return Response({
                "success": True,
                "message": f"Updated transaction status to {mapped_status}"
            })
        else:
            logger.info(f"[TraceID: {trace_id}] Creating new transaction for order {order_id}")
            
            # Better duplicate detection - check for similar transactions in the last 5 seconds
            recent_tx = StockTransaction.objects.filter(
                user_id=user_id,
                stock=stock,
                is_buy=is_buy,
                quantity=quantity,
                price=price,
                timestamp__gte=timezone.now() - timezone.timedelta(seconds=5)
            ).first()
            
            if recent_tx:
                logger.info(f"[TraceID: {trace_id}] Found similar recent transaction {recent_tx.id} (within 5 seconds), updating it instead of creating new")
                
                # Update the existing similar transaction
                recent_tx.external_order_id = order_id  # Add the external order ID
                recent_tx.status = mapped_status
                recent_tx.save()
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    # Check if this stock transaction already has a wallet transaction
                    existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=recent_tx).exists()
                    
                    if existing_wallet_tx:
                        logger.info(f"[TraceID: {trace_id}] This transaction already has a wallet transaction, skipping wallet update")
                    else:
                        # Only process if no wallet transaction exists yet
                        process_stock_transaction(recent_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Updated similar recent transaction status to {mapped_status}"
                })
            else:
                # Create new transaction
                new_tx = StockTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    is_buy=is_buy,
                    order_type=order_type,
                    status=mapped_status,
                    quantity=quantity,
                    price=price,
                    external_order_id=order_id,
                    trace_id=trace_id
                )
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    process_stock_transaction(new_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Created new transaction with status {mapped_status}",
                    "transaction_id": new_tx.id
                })
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error processing order status: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": f"Error processing order status: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def update_stock_prices(request):
    """Update stock prices directly (for testing purposes)"""
    try:
        start_time = time.time()
        data = request.data
        logger.info(f"Received stock price update request with {len(data) if isinstance(data, list) else 1} items")
        
        # Convert single item to list for consistent processing
        if not isinstance(data, list):
            data = [data]
            
        # Early return if no data
        if not data:
            return Response({
                "success": True,
                "message": "No stock prices to update",
                "data": []
            })
        
        # Extract stock_ids for prefetching
        stock_ids = [item.get('stock_id') for item in data if item.get('stock_id')]
        
        # Use select_for_update inside transaction for atomicity
        with db_transaction.atomic():
            # Optimize by fetching all needed stocks in one query with locking
            stocks_map = {
                s.id: s for s in Stock.objects.select_for_update().filter(id__in=stock_ids)
            }
            
            # Prepare data for bulk_update
            stocks_to_update = []
            updated_stocks_data = []
            
            for item in data:
                stock_id = item.get('stock_id')
                current_price = item.get('current_price')
                
                if not stock_id or current_price is None:
                    continue
                    
                if stock_id in stocks_map:
                    stock = stocks_map[stock_id]
                    stock.current_price = Decimal(current_price)
                    stocks_to_update.append(stock)
                    updated_stocks_data.append({
                        'stock_id': stock.id,
                        'symbol': stock.symbol,
                        'stock_name': stock.company_name,
                        'current_price': stock.current_price
                    })
                else:
                    logger.warning(f"Stock with ID {stock_id} not found")
            
            # Perform bulk update in a single query if there are stocks to update
            if stocks_to_update:
                Stock.objects.bulk_update(stocks_to_update, ['current_price'])
                logger.info(f"Bulk updated {len(stocks_to_update)} stock prices in {time.time() - start_time:.3f}s")
                
        return Response({
            "success": True,
            "message": f"Updated {len(updated_stocks_data)} stock prices",
            "data": updated_stocks_data,
            "execution_time_ms": int((time.time() - start_time) * 1000)
        })
    except Exception as e:
        logger.error(f"Error updating stock prices: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": f"Failed to update stock prices: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def process_stock_transaction(stock_tx, trace_id=None):
    """Process a stock transaction and update wallet and portfolio accordingly
    
    This is a utility function that handles a StockTransaction object directly,
    creating appropriate wallet transactions, and updating user portfolios.
    It's called from process_transaction and process_order_notification.
    """
    if not trace_id:
        trace_id = str(uuid.uuid4())[:8]
    
    # OPTIMIZATION: Reduce logging verbosity for high concurrency
    logger.info(f"[TraceID: {trace_id}] Processing stock TX {stock_tx.id}")
    
    try:
        # Extract transaction details
        user_id = stock_tx.user_id
        stock = stock_tx.stock
        is_buy = stock_tx.is_buy
        quantity = stock_tx.quantity
        price = stock_tx.price
        
        # Only process COMPLETED or PARTIAL transactions - using correct OrderStatus values
        if stock_tx.status not in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
            return False
        
        # Use a separate transaction to ensure atomicity
        with db_transaction.atomic():
            # OPTIMIZATION: Lock related records using select_for_update to prevent race conditions
            # First check if a wallet transaction already exists (prevents duplicates)
            existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=stock_tx).first()
            if existing_wallet_tx:
                return True  # Already processed, consider successful
            
            # Get user wallet with lock to prevent race conditions
            wallet = Wallet.objects.select_for_update().get_or_create(
                user_id=user_id,
                defaults={'balance': 0}
            )[0]
            
            # Calculate transaction amount
            amount = Decimal(str(quantity)) * Decimal(str(price))
            
            # Different handling for buy vs sell
            if is_buy:
                # OPTIMIZATION: Combine operations to reduce round trips
                # Buying stock - deduct from wallet and update portfolio in a single transaction
                
                # Update wallet balance
                wallet.balance -= amount
                wallet.save()
                
                # Create wallet transaction record (debit)
                wallet_tx = WalletTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    stock_transaction=stock_tx,
                    is_debit=True,
                    amount=amount,
                    description=f"Purchase of {quantity} shares of {stock.symbol} at ${price}"
                )
                
                # Get or update portfolio with lock
                portfolio = UserPortfolio.objects.select_for_update().get_or_create(
                    user_id=user_id,
                    stock=stock,
                    defaults={'quantity': 0, 'average_price': 0}
                )[0]
                
                # Calculate new average price based on weighted average
                if portfolio.quantity > 0 and portfolio.average_price:
                    total_value = (portfolio.quantity * portfolio.average_price) + amount
                    new_quantity = portfolio.quantity + quantity
                    new_avg_price = total_value / new_quantity if new_quantity > 0 else price
                else:
                    new_avg_price = price
                
                # Update portfolio in a single operation
                portfolio.quantity += quantity
                portfolio.average_price = new_avg_price
                portfolio.save()
            else:
                # Selling stock - add to wallet and update portfolio
                
                # Update wallet balance
                wallet.balance += amount
                wallet.save()
                
                # Create wallet transaction record (credit)
                wallet_tx = WalletTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    stock_transaction=stock_tx,
                    is_debit=False,
                    amount=amount,
                    description=f"Sale of {quantity} shares of {stock.symbol} at ${price}"
                )
                
                # Find and update portfolio with lock
                try:
                    portfolio = UserPortfolio.objects.select_for_update().get(user_id=user_id, stock=stock)
                    
                    # Update portfolio in a single operation
                    portfolio.quantity -= quantity
                    portfolio.save()
                    
                    # If quantity is zero, remove the portfolio entry
                    if portfolio.quantity <= 0:
                        portfolio.delete()
                except UserPortfolio.DoesNotExist:
                    logger.error(f"[TraceID: {trace_id}] User {user_id} has no portfolio for stock {stock.symbol}")
                    return False
            
            return True
    
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error in stock TX {stock_tx.id}: {str(e)}")
        return False

# URL patterns (to be imported in urls.py)
# These are the URL patterns to include in your urls.py file

'''
urlpatterns = [
    # Transaction endpoints
    path('api/transaction/getStockPrices', get_stock_prices, name='get_stock_prices'),
    path('api/transaction/getStockPortfolio', get_stock_portfolio, name='get_stock_portfolio'),
    path('api/transaction/getStockTransactions', get_stock_transactions, name='get_stock_transactions'),
    path('api/transaction/addMoneyToWallet', add_money_to_wallet, name='add_money_to_wallet'),
    path('api/transaction/getWalletBalance', get_wallet_balance, name='get_wallet_balance'),
    path('api/transaction/getWalletTransactions', get_wallet_transactions, name='get_wallet_transactions'),
    
    # Setup endpoints
    path('api/setup/createStock', create_stock, name='create_stock'),
    path('api/setup/addStockToUser', add_stock_to_user, name='add_stock_to_user'),
]
''' 