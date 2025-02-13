from decimal import Decimal
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from django.shortcuts import get_object_or_404

from .models import Wallet, Stock, StockHolding, Order, Transaction
from .serializers import (
    WalletSerializer, StockSerializer, StockHoldingSerializer,
    OrderSerializer, TransactionSerializer
)

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
    """
    Place a new trading order
    
    Expected payload:
    {
        "stock_symbol": "AAPL",
        "order_type": "BUY",
        "quantity": 10,
        "price": 150.00
    }
    """
    try:
        # Get user's wallet
        wallet = get_object_or_404(Wallet, user_id=request.user.id)
        
        # Get stock
        stock = get_object_or_404(Stock, symbol=request.data.get('stock_symbol'))
        
        # Prepare order data
        order_data = {
            'wallet': wallet.id,
            'stock': stock.id,
            'order_type': request.data.get('order_type'),
            'quantity': request.data.get('quantity'),
            'price': request.data.get('price')
        }
        
        # Validate and create order
        serializer = OrderSerializer(data=order_data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        with transaction.atomic():
            # Check if user has sufficient funds for buy order
            if order_data['order_type'] == 'BUY':
                total_cost = Decimal(str(order_data['quantity'])) * Decimal(str(order_data['price']))
                if wallet.balance < total_cost:
                    return Response(
                        {'error': 'Insufficient funds'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Reserve funds
                wallet.balance -= total_cost
                wallet.save()
            
            # For sell orders, check if user has sufficient stocks
            elif order_data['order_type'] == 'SELL':
                holding = StockHolding.objects.filter(
                    wallet=wallet,
                    stock=stock
                ).first()
                
                if not holding or holding.quantity < order_data['quantity']:
                    return Response(
                        {'error': 'Insufficient stocks'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Create the order
            order = serializer.save()
            
            # TODO: Send order to order matching engine
            # This would typically involve sending a message to a queue
            # for processing by the order matching engine
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_portfolio(request):
    """
    Get user's portfolio including wallet balance and stock holdings
    """
    try:
        wallet = get_object_or_404(Wallet, user_id=request.user.id)
        holdings = StockHolding.objects.filter(wallet=wallet)
        
        return Response({
            'wallet': WalletSerializer(wallet).data,
            'holdings': StockHoldingSerializer(holdings, many=True).data
        })
        
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 