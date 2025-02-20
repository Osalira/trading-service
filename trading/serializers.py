from rest_framework import serializers
from .models import Wallet, Stock, StockHolding, Order, Transaction

class StockSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stock
        fields = ['id', 'symbol', 'name', 'current_price', 'total_shares', 'shares_available', 'created_at', 'last_updated']
        read_only_fields = ['created_at', 'last_updated']

class StockHoldingSerializer(serializers.ModelSerializer):
    stock_name = serializers.CharField(source='stock.name', read_only=True)
    
    class Meta:
        model = StockHolding
        fields = ['id', 'stock_id', 'stock_name', 'quantity', 'average_price', 'updated_at']
        read_only_fields = ['updated_at']

class WalletSerializer(serializers.ModelSerializer):
    holdings = StockHoldingSerializer(many=True, read_only=True)
    
    class Meta:
        model = Wallet
        fields = ['id', 'user_id', 'balance', 'holdings', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class OrderSerializer(serializers.ModelSerializer):
    stock_name = serializers.CharField(source='stock.name', read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'stock_id', 'stock_name', 'order_type',
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
    stock_name = serializers.CharField(source='order.stock.name', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'order_id', 'order_type', 'stock_name',
            'executed_price', 'executed_quantity',
            'transaction_fee', 'executed_at'
        ]
        read_only_fields = ['executed_at'] 