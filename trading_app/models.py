from django.db import models
from django.utils import timezone
from enum import Enum

class OrderType(models.TextChoices):
    MARKET = 'Market', 'Market'
    LIMIT = 'Limit', 'Limit'

class OrderStatus(models.TextChoices):
    PENDING = 'Pending', 'Pending'
    IN_PROGRESS = 'InProgress', 'In Progress'
    COMPLETED = 'Completed', 'Completed'
    PARTIALLY_COMPLETE = 'Partially_complete', 'Partially Complete'
    CANCELLED = 'Cancelled', 'Cancelled'
    REJECTED = 'Rejected', 'Rejected'

class Stock(models.Model):
    """Stock model representing a company's stock"""
    symbol = models.CharField(max_length=10, unique=True)
    company_name = models.CharField(max_length=100)
    current_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    total_shares = models.BigIntegerField(default=0)
    available_shares = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.symbol} - {self.company_name} (${self.current_price})"
    
    class Meta:
        db_table = 'stocks'
        ordering = ['symbol']

class UserPortfolio(models.Model):
    """Portfolio model representing a user's stock holdings"""
    user_id = models.IntegerField()
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE, related_name='portfolio_entries')
    quantity = models.BigIntegerField(default=0)
    average_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_portfolios'
        unique_together = ('user_id', 'stock')
        ordering = ['user_id', 'stock__symbol']
    
    def __str__(self):
        return f"User {self.user_id}: {self.stock.symbol} - {self.quantity} shares"

class Wallet(models.Model):
    """Wallet model for tracking user account balance"""
    user_id = models.IntegerField(unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'wallets'
    
    def __str__(self):
        return f"User {self.user_id}: ${self.balance}"

class StockTransaction(models.Model):
    """Model for stock buy/sell transactions"""
    user_id = models.IntegerField(db_index=True)
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE, related_name='transactions')
    is_buy = models.BooleanField(default=True)
    order_type = models.CharField(max_length=20, choices=OrderType.choices, default='LIMIT')
    status = models.CharField(max_length=20, choices=OrderStatus.choices, default=OrderStatus.PENDING)
    quantity = models.BigIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    parent_transaction = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='child_transactions')
    wallet_transaction = models.OneToOneField('WalletTransaction', on_delete=models.SET_NULL, null=True, blank=True, related_name='related_stock_tx')
    external_order_id = models.BigIntegerField(null=True, blank=True, db_index=True, help_text="ID of the order in the matching engine")
    
    class Meta:
        db_table = 'stock_transactions'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user_id', 'stock', 'is_buy']),
        ]
    
    def __str__(self):
        action = "Buy" if self.is_buy else "Sell"
        return f"{action} {self.quantity} {self.stock.symbol} at ${self.price} - {self.status}"

class WalletTransaction(models.Model):
    """Model for wallet transactions (deposits, withdrawals, stock purchases, stock sales)"""
    user_id = models.IntegerField()
    stock = models.ForeignKey(Stock, on_delete=models.SET_NULL, null=True, blank=True, related_name='wallet_transactions')
    stock_transaction = models.ForeignKey('StockTransaction', on_delete=models.SET_NULL, null=True, blank=True, related_name='wallet_transactions', db_column='stock_transaction_id')
    is_debit = models.BooleanField()  # True for deductions (buy stock), False for additions (add money, sell stock)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'wallet_transactions'
        ordering = ['-timestamp']
    
    def __str__(self):
        action = "Debit" if self.is_debit else "Credit"
        return f"{action} ${self.amount} for User {self.user_id} - {self.description}"
