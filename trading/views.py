from decimal import Decimal
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from django.shortcuts import get_object_or_404
import jwt
import logging
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import Wallet, Stock, StockHolding, Order, Transaction
from .serializers import (
    WalletSerializer, StockSerializer, StockHoldingSerializer,
    OrderSerializer, TransactionSerializer
)
from .validators import validate_order_parameters

logger = logging.getLogger('trading')

class WalletViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user wallets
    """
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Wallet.objects.filter(user_id=self.request.user.id)

class StockViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving stock information
    """
    queryset = Stock.objects.all()
    serializer_class = StockSerializer
    permission_classes = [IsAuthenticated]

class OrderViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing orders
    """
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get orders for the authenticated user
        """
        user_id = self.request.user.id
        wallet = Wallet.objects.get_or_create(user_id=user_id)[0]
        return Order.objects.filter(wallet=wallet).order_by('-created_at')

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def place_order(request):
    """Place a new stock order"""
    try:
        validated_data = validate_order_parameters(request.data, request.user)
        
        with transaction.atomic():
            order = Order.objects.create(
                wallet=validated_data['wallet'],
                stock=validated_data['stock'],
                quantity=validated_data['quantity'],
                order_type=validated_data['order_type'],
                price=validated_data['price'],
                status='PENDING'
            )
            
            # For company sell orders of their own stock, process immediately
            if (request.user.account_type == 'company' and 
                validated_data['order_type'] == 'SELL' and 
                validated_data['stock'].company_id == request.user.id):
                
                # Update stock price and available shares
                stock = validated_data['stock']
                stock.current_price = validated_data['price']
                stock.shares_available = validated_data['quantity']
                stock.total_shares = max(stock.total_shares, validated_data['quantity'])
                stock.save()
                
                # Update or create holding
                holding, _ = StockHolding.objects.get_or_create(
                    wallet=validated_data['wallet'],
                    stock=stock,
                    defaults={
                        'quantity': validated_data['quantity'],
                        'average_price': validated_data['price']
                    }
                )
                holding.quantity = validated_data['quantity']
                holding.average_price = validated_data['price']
                holding.save()
                
                # Create transaction record
                Transaction.objects.create(
                    order=order,
                    executed_price=validated_data['price'],
                    executed_quantity=validated_data['quantity'],
                    transaction_fee=Decimal('0.00')  # No fee for company orders
                )
                
                order.status = 'COMPLETED'
                order.save()
            
            # For market buy orders, process immediately
            elif validated_data['order_type'] == 'BUY':
                process_market_order(order)
            
            return Response({
                'success': True,
                'data': {
                    'order_id': order.id,
                    'status': order.status
                }
            })
            
    except ValidationError as e:
        logger.warning(f"Order validation failed: {str(e)}")
        return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(f"Error placing order: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def process_market_order(order):
    """Process a market order immediately"""
    try:
        with transaction.atomic():
            if order.order_type == 'BUY':
                # Calculate total cost
                total_cost = order.quantity * order.stock.current_price
                
                # Update wallet balance
                order.wallet.balance -= total_cost
                order.wallet.save()
                
                # Update or create stock holding
                holding, created = StockHolding.objects.get_or_create(
                    wallet=order.wallet,
                    stock=order.stock,
                    defaults={
                        'quantity': 0,
                        'average_price': order.stock.current_price
                    }
                )
                
                if not created:
                    # Calculate new average price
                    total_value = (holding.quantity * holding.average_price) + total_cost
                    total_quantity = holding.quantity + order.quantity
                    holding.average_price = total_value / total_quantity
                
                holding.quantity += order.quantity
                holding.save()
                
                # Update stock available shares
                order.stock.shares_available -= order.quantity
                order.stock.save()
                
            else:  # SELL
                # Update stock holding
                holding = StockHolding.objects.get(
                    wallet=order.wallet,
                    stock=order.stock
                )
                holding.quantity -= order.quantity
                
                if holding.quantity > 0:
                    holding.save()
                else:
                    holding.delete()
                
                # Update wallet balance
                total_value = order.quantity * order.stock.current_price
                order.wallet.balance += total_value
                order.wallet.save()
                
                # Update stock available shares
                order.stock.shares_available += order.quantity
                order.stock.save()
            
            # Create transaction record
            Transaction.objects.create(
                order=order,
                executed_price=order.stock.current_price,
                executed_quantity=order.quantity,
                transaction_fee=Decimal('0.00')  # Add fee calculation if needed
            )
            
            order.status = 'COMPLETED'
            order.save()
            
    except Exception as e:
        logger.error(f"Error processing market order {order.id}: {str(e)}")
        order.status = 'FAILED'
        order.save()
        raise

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_portfolio(request):
    """Get user's portfolio"""
    logger.info("=== Starting get_portfolio endpoint ===")
    logger.debug(f"User ID: {request.user.id}, Account Type: {request.user.account_type}")
    
    try:
        user_id = request.user.id
        wallet = Wallet.objects.get_or_create(user_id=user_id)[0]
        logger.debug(f"Found wallet with balance: {wallet.balance}")
        
        # Get regular holdings
        holdings = StockHolding.objects.filter(wallet=wallet).select_related('stock')
        logger.debug(f"Found {holdings.count()} holdings")
        
        # For company accounts, also include their created stocks
        total_value = Decimal('0.00')
        portfolio_data = []
        
        # Add regular holdings
        for holding in holdings:
            value = Decimal(str(holding.quantity)) * holding.stock.current_price
            total_value += value
            holding_data = {
                'symbol': holding.stock.symbol,
                'quantity': holding.quantity,
                'average_price': float(holding.average_price),
                'current_price': float(holding.stock.current_price),
                'profit_loss': float(value - (holding.average_price * holding.quantity))
            }
            portfolio_data.append(holding_data)
            logger.debug(f"Added holding: {holding_data}")
        
        # For company accounts, add their created stocks
        if request.user.account_type == 'company':
            company_stocks = Stock.objects.filter(company_id=user_id)
            logger.debug(f"Found {company_stocks.count()} company stocks")
            for stock in company_stocks:
                value = Decimal(str(stock.shares_available)) * stock.current_price
                total_value += value
                stock_data = {
                    'symbol': stock.symbol,
                    'quantity': stock.shares_available,
                    'average_price': float(stock.current_price),
                    'current_price': float(stock.current_price),
                    'profit_loss': 0.0  # No profit/loss for company's own stock
                }
                portfolio_data.append(stock_data)
                logger.debug(f"Added company stock: {stock_data}")
        
        # Get active orders count
        active_orders = Order.objects.filter(
            wallet=wallet,
            status__in=['PENDING', 'PARTIALLY_COMPLETE']
        ).count()
        logger.debug(f"Active orders count: {active_orders}")
        
        response_data = {
            'success': True,
            'data': {
                'holdings': portfolio_data,
                'total_value': float(total_value),
                'active_orders': active_orders
            }
        }
        logger.info("Successfully retrieved portfolio data")
        logger.debug(f"Response data: {response_data}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"Error getting portfolio: {str(e)}", exc_info=True)
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        logger.info("=== Ending get_portfolio endpoint ===")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_stock(request):
    """
    Create a new stock with initial zero shares and price.
    Only company accounts can create stocks.
    """
    logger.info("=== Starting create_stock endpoint ===")
    logger.debug(f"Request data: {request.data}")
    logger.debug(f"User info - ID: {request.user.id}, Type: {request.user.account_type}")
    
    if request.user.account_type != 'company':
        logger.warning(f"Unauthorized attempt to create stock by non-company account. Account type: {request.user.account_type}")
        return Response({
            'success': False,
            'data': {
                'error': 'Only company accounts can create stocks'
            }
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        with transaction.atomic():
            # Create or get the company's wallet
            wallet, _ = Wallet.objects.get_or_create(user_id=request.user.id)
            
            # Create the stock
            stock = Stock.objects.create(
                symbol=request.data.get('symbol', '').upper(),
                name=request.data.get('stock_name', ''),
                current_price=Decimal('0.00'),
                total_shares=0,
                shares_available=0,
                company_id=request.user.id
            )
            
            # Create initial holding for the company
            StockHolding.objects.create(
                wallet=wallet,
                stock=stock,
                quantity=0,
                average_price=Decimal('0.00')
            )
            
            return Response({
                'success': True,
                'data': {
                    'stock_id': stock.id,
                    'symbol': stock.symbol,
                    'name': stock.name
                }
            })
            
    except Exception as e:
        logger.error(f"Error creating stock: {str(e)}", exc_info=True)
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        logger.info("=== Ending create_stock endpoint ===")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_stock_to_user(request):
    """
    Add stock to user's portfolio.
    
    Expected payload:
    {
        "stock_id": int,
        "quantity": int
    }
    """
    try:
        stock_id = request.data.get('stock_id')
        quantity = request.data.get('quantity')
        
        if not all([stock_id, quantity]):
            return Response({
                'success': False,
                'data': {
                    'error': 'Stock ID and quantity are required'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        stock = get_object_or_404(Stock, id=stock_id)
        
        # Check if there are enough shares available
        if stock.shares_available < quantity:
            return Response({
                'success': False,
                'data': {
                    'error': 'Insufficient shares available'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        wallet, _ = Wallet.objects.get_or_create(user_id=request.user.id)
        
        holding, created = StockHolding.objects.get_or_create(
            wallet=wallet,
            stock=stock,
            defaults={'average_price': stock.current_price, 'quantity': 0}
        )
        
        # Update stock holding and available shares
        holding.quantity += quantity
        stock.shares_available -= quantity
        
        holding.save()
        stock.save()
        
        return Response({
            'success': True,
            'data': None
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_stock_portfolio(request):
    """
    Get user's stock portfolio sorted by stock name in lexicographically decreasing order.
    """
    try:
        wallet = get_object_or_404(Wallet, user_id=request.user.id)
        holdings = StockHolding.objects.filter(wallet=wallet).select_related('stock')
        
        portfolio_data = [{
            'stock_id': holding.stock.id,
            'stock_name': holding.stock.name,
            'quantity_owned': holding.quantity,
            'updated_at': holding.updated_at.isoformat()
        } for holding in holdings]
        
        # Sort by stock name in lexicographically decreasing order
        portfolio_data.sort(key=lambda x: x['stock_name'], reverse=True)
        
        return Response({
            'success': True,
            'data': portfolio_data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def place_stock_order(request):
    """Place a new stock order"""
    try:
        validated_data = validate_order_parameters(request.data, request.user)
        
        order = Order.objects.create(
            wallet=validated_data['wallet'],
            stock=validated_data['stock'],
            quantity=validated_data['quantity'],
            order_type=validated_data['order_type'],
            limit_price=validated_data['limit_price'],
            order_action=validated_data['order_action'],
            status='PENDING'
        )
        
        # Process order immediately for market orders
        if order.order_type == 'MARKET':
            process_market_order(order)
        
        return Response({
            'success': True,
            'data': {
                'order_id': order.id,
                'status': order.status
            }
        })
        
    except ValidationError as e:
        logger.warning(f"Order validation failed: {str(e)}")
        return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(f"Error placing order: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_stock_transaction(request):
    """
    Cancel a pending or partially complete stock transaction.
    
    Expected payload:
    {
        "stock_tx_id": int
    }
    """
    try:
        tx_id = request.data.get('stock_tx_id')
        if not tx_id:
            return Response({
                'success': False,
                'data': {
                    'error': 'Transaction ID is required'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        order = get_object_or_404(Order, id=tx_id, wallet__user_id=request.user.id)
        
        # Check if order can be cancelled
        if order.status not in [Order.OrderStatus.PENDING, Order.OrderStatus.PARTIALLY_COMPLETE]:
            return Response({
                'success': False,
                'data': {
                    'error': f'Only pending or partially complete orders can be cancelled. Current status: {order.status}'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        
        with transaction.atomic():
            # If order is partially complete, we need to handle the remaining quantity
            if order.status == Order.OrderStatus.PARTIALLY_COMPLETE:
                # Get the executed quantity from transaction
                executed_qty = order.transaction.executed_quantity if hasattr(order, 'transaction') else 0
                remaining_qty = order.quantity - executed_qty
                
                # Update order quantity to reflect only the executed portion
                order.quantity = executed_qty
                order.status = Order.OrderStatus.COMPLETED
                order.save()
                
                # Create a new cancelled order for the remaining quantity
                cancelled_order = Order.objects.create(
                    wallet=order.wallet,
                    stock=order.stock,
                    order_type=order.order_type,
                    quantity=remaining_qty,
                    price=order.price,
                    status=Order.OrderStatus.CANCELLED
                )
                
                return Response({
                    'success': True,
                    'data': {
                        'message': 'Partially complete order processed',
                        'completed_order_id': order.id,
                        'cancelled_order_id': cancelled_order.id
                    }
                }, status=status.HTTP_200_OK)
            else:
                # For pending orders, simply cancel the entire order
                order.status = Order.OrderStatus.CANCELLED
                order.save()
                
                return Response({
                    'success': True,
                    'data': {
                        'message': 'Order cancelled successfully',
                        'order_id': order.id
                    }
                }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_stock_prices(request):
    """Get current stock prices"""
    try:
        stocks = Stock.objects.all().order_by('-name')
        serialized_stocks = StockSerializer(stocks, many=True).data
        
        return Response({
            'success': True,
            'data': {
                'stocks': serialized_stocks
            }
        })
    except Exception as e:
        logger.error(f"Error getting stock prices: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_money_to_wallet(request):
    """Add money to user's wallet"""
    try:
        user_id = request.user.user_id
        amount = Decimal(request.data.get('amount', 0))
        
        if amount <= 0:
            return Response({
                'success': False,
                'data': {
                    'error': 'Amount must be positive'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        
        wallet, created = Wallet.objects.get_or_create(user_id=user_id)
        wallet.balance += amount
        wallet.save()
        
        return Response({
            'success': True,
            'data': {
                'balance': float(wallet.balance)
            }
        })
    except Exception as e:
        logger.error(f"Error adding money to wallet: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_balance(request):
    """
    Get user's wallet balance. Creates a wallet if it doesn't exist.
    """
    try:
        wallet, created = Wallet.objects.get_or_create(user_id=request.user.id)
        
        return Response({
            'success': True,
            'data': {
                'balance': float(wallet.balance)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting wallet balance: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_company_stocks(request):
    """
    Get all stocks created by the company.
    Only accessible by company accounts.
    """
    logger.debug(f"Request headers: {dict(request.headers)}")
    
    try:
        # Verify company account
        if request.user.account_type != 'company':
            logger.warning(f"Unauthorized attempt to access company stocks. Account type: {request.user.account_type}")
            return Response({
                'success': False,
                'data': {
                    'error': 'Only company accounts can access this endpoint'
                }
            }, status=status.HTTP_403_FORBIDDEN)

        # Get stocks created by this company
        stocks = Stock.objects.filter(company_id=request.user.id)
        serializer = StockSerializer(stocks, many=True)
        
        return Response({
            'success': True,
            'data': {
                'stocks': serializer.data
            }
        })
        
    except Exception as e:
        logger.error(f"Error in get_company_stocks: {str(e)}", exc_info=True)
        return Response({
            'success': False,
            'data': {
                'error': 'Failed to fetch company stocks'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_orders(request):
    """
    Get all orders for the authenticated user
    """
    logger.info("=== Starting get_orders endpoint ===")
    logger.debug(f"User ID: {request.user.id}, Account Type: {request.user.account_type}")
    
    try:
        user_id = request.user.id
        wallet = Wallet.objects.get_or_create(user_id=user_id)[0]
        logger.debug(f"Found wallet: {wallet.id}")
        
        # Get orders with related stock information
        orders = Order.objects.filter(wallet=wallet)\
            .select_related('stock')\
            .order_by('-created_at')
        
        logger.debug(f"Found {orders.count()} orders")
        
        # Prepare order data with stock information
        orders_data = []
        for order in orders:
            order_data = {
                'id': order.id,
                'symbol': order.stock.symbol,
                'type': order.order_type,
                'quantity': order.quantity,
                'price': float(order.price),
                'status': order.status,
                'created_at': order.created_at.isoformat()
            }
            orders_data.append(order_data)
            logger.debug(f"Added order: {order_data}")
        
        response_data = {
            'success': True,
            'data': orders_data
        }
        logger.info("Successfully retrieved orders")
        logger.debug(f"Response data: {response_data}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"Error getting orders: {str(e)}", exc_info=True)
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        logger.info("=== Ending get_orders endpoint ===") 