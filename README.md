# Trading Service

This service handles trading operations for the Day Trading System, including order placement, wallet management, and portfolio tracking.

## Features

- Place buy/sell orders
- Manage user wallets and balances
- Track stock holdings and transactions
- Real-time portfolio view
- Integration with order matching engine

## Prerequisites

- Python 3.8+
- PostgreSQL
- Virtual Environment (recommended)

## Setup

1. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (create a .env file):
```env
# Django settings
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# Database settings
DB_NAME=daytrading
DB_USER=postgres
DB_PASSWORD=postgres
DB_HOST=localhost
DB_PORT=5432

# CORS settings
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

4. Apply database migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

5. Create a superuser (optional):
```bash
python manage.py createsuperuser
```

## Running the Service

Start the development server:
```bash
python manage.py runserver
```

The service will run on `http://localhost:8000`

## API Endpoints

### Trading Operations

- `POST /api/trading/orders/place/` - Place a new order
  ```json
  {
    "stock_symbol": "AAPL",
    "order_type": "BUY",
    "quantity": 10,
    "price": 150.00
  }
  ```

- `GET /api/trading/portfolio/` - Get user's portfolio

### Wallet Management

- `GET /api/trading/wallets/` - List user's wallets
- `POST /api/trading/wallets/` - Create a new wallet
- `GET /api/trading/wallets/{id}/` - Get wallet details

### Stock Information

- `GET /api/trading/stocks/` - List available stocks
- `GET /api/trading/stocks/{id}/` - Get stock details

## Authentication

The service uses JWT tokens for authentication. Include the token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

## Development

- Run tests:
```bash
python manage.py test
```

- Check code style:
```bash
flake8
```

## Security Notes

- All endpoints require authentication
- Transactions use atomic operations to ensure data consistency
- Input validation is performed on all requests
- Sensitive configuration is managed through environment variables 