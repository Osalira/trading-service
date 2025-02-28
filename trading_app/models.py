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
    current_price = models.DecimalField(max_digits=10, decimal_places=2)
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
    quantity = models.IntegerField(default=0)
    average_price = models.DecimalField(max_digits=10, decimal_places=2)
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
    user_id = models.IntegerField()
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE, related_name='transactions')
    is_buy = models.BooleanField()  # True for buy, False for sell
    order_type = models.CharField(max_length=20, choices=OrderType.choices)
    status = models.CharField(max_length=20, choices=OrderStatus.choices)
    quantity = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    parent_transaction = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='child_transactions')
    wallet_transaction = models.ForeignKey('WalletTransaction', on_delete=models.SET_NULL, null=True, blank=True, related_name='stock_transaction')
    
    class Meta:
        db_table = 'stock_transactions'
        ordering = ['-timestamp']
    
    def __str__(self):
        action = "Buy" if self.is_buy else "Sell"
        return f"{action} {self.quantity} {self.stock.symbol} at ${self.price} - {self.status}"

class WalletTransaction(models.Model):
    """Model for wallet transactions (deposits, withdrawals, stock purchases, stock sales)"""
    user_id = models.IntegerField()
    stock = models.ForeignKey(Stock, on_delete=models.SET_NULL, null=True, blank=True, related_name='wallet_transactions')
    stock_transaction_id = models.IntegerField(null=True, blank=True)
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
