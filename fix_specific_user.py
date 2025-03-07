from trading_app.models import StockTransaction, WalletTransaction

# This script directly fixes the specific issue for user ID 2
# where wallet transaction 3 points to stock_tx_id 3 but should point to stock_tx_id 4

print("Running targeted fix for user ID 2 wallet and stock transactions...")

# Get the specific wallet transaction (ID 3) for user 2
try:
    wallet_tx = WalletTransaction.objects.get(id=3, user_id=2)
    print(f"Found wallet transaction {wallet_tx.id} for user {wallet_tx.user_id}")
    print(f"  Currently links to stock_tx_id: {wallet_tx.stock_transaction_id}")
    print(f"  Description: {wallet_tx.description}")
    print(f"  Amount: {wallet_tx.amount}")
    print(f"  Timestamp: {wallet_tx.timestamp}")
except WalletTransaction.DoesNotExist:
    print("Wallet transaction 3 not found for user 2")
    exit()

# Get the stock transaction (ID 4) for user 2
try:
    stock_tx = StockTransaction.objects.get(id=4, user_id=2)
    print(f"\nFound stock transaction {stock_tx.id} for user {stock_tx.user_id}")
    print(f"  Currently has wallet_tx_id: {stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None}")
    print(f"  Stock ID: {stock_tx.stock_id}")
    print(f"  Is Buy: {stock_tx.is_buy}")
    print(f"  Quantity: {stock_tx.quantity}")
    print(f"  Price: {stock_tx.price}")
    print(f"  Timestamp: {stock_tx.timestamp}")
except StockTransaction.DoesNotExist:
    print("Stock transaction 4 not found for user 2")
    exit()

# Check if stock transaction 3 actually exists
try:
    stock_tx_3 = StockTransaction.objects.get(id=3)
    print(f"\nStock transaction 3 exists and belongs to user {stock_tx_3.user_id}")
except StockTransaction.DoesNotExist:
    print("\nStock transaction 3 does not exist")
    stock_tx_3 = None

# Direct fix: Update the links in both directions
print("\nApplying fix to create bidirectional link between wallet transaction 3 and stock transaction 4...")

# Update the wallet transaction to point to stock transaction 4
wallet_tx.stock_transaction = stock_tx
wallet_tx.stock_transaction_id = stock_tx.id
wallet_tx.save(update_fields=['stock_transaction', 'stock_transaction_id'])

# Update the stock transaction to point to wallet transaction 3
stock_tx.wallet_transaction = wallet_tx
stock_tx.save(update_fields=['wallet_transaction'])

# Verify the fix
wallet_tx.refresh_from_db()
stock_tx.refresh_from_db()

print("\nVerifying fix:")
print(f"Wallet transaction {wallet_tx.id} now links to stock_tx_id: {wallet_tx.stock_transaction_id}")
print(f"Stock transaction {stock_tx.id} now has wallet_tx_id: {stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None}")

if wallet_tx.stock_transaction_id == stock_tx.id and stock_tx.wallet_transaction_id == wallet_tx.id:
    print("\nFIX SUCCESSFUL: Bidirectional link established correctly")
else:
    print("\nWARNING: Fix did not create proper bidirectional link") 