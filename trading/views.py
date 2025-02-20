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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def place_order(request):
    """Place a new stock order"""
    try:
        validated_data = validate_order_parameters(request.data, request.user)
        
        order = Order.objects.create(
            wallet=validated_data['wallet'],
            stock=validated_data['stock'],
            quantity=validated_data['quantity'],
            order_type=validated_data['order_type'],
            price=validated_data['price'],
            status='PENDING'
        )
        
        # Process order immediately for market orders
        if validated_data['order_type'] == 'MARKET':
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
        if order.order_action == 'BUY':
            # Update wallet balance
            order.wallet.balance -= (order.quantity * order.stock.current_price)
            order.wallet.save()
            
            # Update or create stock holding
            holding, created = StockHolding.objects.get_or_create(
                wallet=order.wallet,
                stock=order.stock,
                defaults={'quantity': 0}
            )
            holding.quantity += order.quantity
            holding.save()
            
        else:  # SELL
            # Update stock holding
            holding = StockHolding.objects.get(
                wallet=order.wallet,
                stock=order.stock
            )
            holding.quantity -= order.quantity
            holding.save()
            
            if holding.quantity == 0:
                holding.delete()
            
            # Update wallet balance
            order.wallet.balance += (order.quantity * order.stock.current_price)
            order.wallet.save()
        
        order.status = 'COMPLETED'
        order.completed_at = timezone.now()
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
    try:
        user_id = request.user.user_id
        wallet = get_object_or_404(Wallet, user_id=user_id)
        holdings = StockHolding.objects.filter(wallet=wallet).order_by('-stock__name')
        
        serialized_holdings = StockHoldingSerializer(holdings, many=True).data
        
        return Response({
            'success': True,
            'data': {
                'holdings': serialized_holdings,
                'total_value': sum(h.quantity * h.stock.current_price for h in holdings)
            }
        })
    except Exception as e:
        logger.error(f"Error getting portfolio: {str(e)}")
        return Response({
            'success': False,
            'data': {
                'error': str(e)
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_stock(request):
    """
    Create a new stock with initial zero shares and price.
    Only company accounts can create stocks.
    """
    logger.info("=== Starting create_stock endpoint ===")
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request path: {request.path}")
    logger.debug(f"Request content type: {request.content_type}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    logger.debug(f"Request data: {request.data}")
    logger.debug(f"User info - ID: {request.user.id}, Type: {request.user.account_type}")
    
    if request.method != 'POST':
        logger.warning(f"Method {request.method} not allowed")
        return Response({
            'success': False,
            'data': {
                'error': f'Method {request.method} not allowed'
            }
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    try:
        # Verify company account
        if request.user.account_type != 'company':
            logger.warning(f"Unauthorized attempt to create stock by non-company account. Account type: {request.user.account_type}")
            return Response({
                'success': False,
                'data': {
                    'error': 'Only company accounts can create stocks'
                }
            }, status=status.HTTP_403_FORBIDDEN)

        # Validate request data
        if 'stock_name' not in request.data:
            logger.warning("Missing stock_name in request data")
            return Response({
                'success': False,
                'data': {
                    'error': 'stock_name is required'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        stock_name = request.data['stock_name']
        logger.info(f"Creating stock with name: {stock_name}")

        # Create stock with zero shares and price
        stock = Stock.objects.create(
            name=stock_name,
            symbol=stock_name.upper(),
            current_price=Decimal('0.00'),
            total_shares=0,
            shares_available=0,
            company_id=request.user.id
        )
        
        logger.info(f"Stock created successfully. ID: {stock.id}, Symbol: {stock.symbol}")
        
        return Response({
            'success': True,
            'data': {
                'message': 'Stock created successfully',
                'stock_id': stock.id,
                'symbol': stock.symbol
            }
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Unexpected error creating stock: {str(e)}", exc_info=True)
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