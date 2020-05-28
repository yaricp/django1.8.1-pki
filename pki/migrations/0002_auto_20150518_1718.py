# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='public',
            field=models.BooleanField(default=False, help_text=b'Public certificate'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='public',
            field=models.BooleanField(default=False, help_text=b'Public certificate'),
        ),
    ]
