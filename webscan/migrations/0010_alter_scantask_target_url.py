# Generated by Django 5.1.2 on 2024-11-21 22:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webscan', '0009_alter_scanresults_result_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scantask',
            name='target_url',
            field=models.URLField(help_text='扫描目标域名或IP', max_length=255),
        ),
    ]
