# Generated by Django 5.1.4 on 2025-03-04 20:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trading_app', '0004_alter_userportfolio_average_price'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stocktransaction',
            name='quantity',
            field=models.BigIntegerField(),
        ),
        migrations.AlterField(
            model_name='userportfolio',
            name='quantity',
            field=models.BigIntegerField(default=0),
        ),
    ]
