# Generated by Django 5.1.4 on 2025-03-10 03:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('trading_app', '0007_alter_stocktransaction_wallet_transaction'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='stocktransaction',
            name='wallet_transaction',
        ),
    ]
