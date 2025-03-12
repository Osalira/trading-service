from decimal import Decimal
import json

class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that:
    1. Converts Decimal to int if it's a whole number
    2. Otherwise converts Decimal to float (which will use standard JSON number representation)
    """
    def default(self, obj):
        if isinstance(obj, Decimal):
            # If it's a whole number, convert to int
            if obj % 1 == 0:
                return int(obj)
            # Otherwise convert to float for regular JSON number formatting
            return float(obj)
        return super().default(obj) 