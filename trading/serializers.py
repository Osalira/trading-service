from rest_framework import serializers
from .models import Wallet, Stock, StockHolding, Order, Transaction

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['id', 'user_id', 'balance', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class StockSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stock
        fields = ['id', 'symbol', 'name', 'current_price', 'last_updated']
        read_only_fields = ['last_updated']

class StockHoldingSerializer(serializers.ModelSerializer):
    stock_symbol = serializers.CharField(source='stock.symbol', read_only=True)
    
    class Meta:
        model = StockHolding
        fields = ['id', 'wallet', 'stock', 'stock_symbol', 'quantity', 'average_price', 'updated_at']
        read_only_fields = ['updated_at']

class OrderSerializer(serializers.ModelSerializer):
    stock_symbol = serializers.CharField(source='stock.symbol', read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'wallet', 'stock', 'stock_symbol', 'order_type',
            'quantity', 'price', 'status', 'created_at', 'updated_at'
        ]
        read_only_fields = ['status', 'created_at', 'updated_at']

    def validate(self, data):
        """
        Custom validation for order creation
        """
        if data['quantity'] <= 0:
            raise serializers.ValidationError("Quantity must be positive")
        if data['price'] <= 0:
            raise serializers.ValidationError("Price must be positive")
        return data

class TransactionSerializer(serializers.ModelSerializer):
    order_type = serializers.CharField(source='order.order_type', read_only=True)
    stock_symbol = serializers.CharField(source='order.stock.symbol', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'order', 'order_type', 'stock_symbol',
            'executed_price', 'executed_quantity',
            'transaction_fee', 'executed_at'
        ]
        read_only_fields = ['executed_at'] 