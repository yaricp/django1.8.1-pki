# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('pki', '0002_auto_20150518_1718'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='owner',
            field=models.ForeignKey(
                default=2,
                verbose_name=b'Owner of certificate',
                to=settings.AUTH_USER_MODEL,
                on_delete=models.SET_DEFAULT
            ),
            preserve_default=False,

        ),
    ]
