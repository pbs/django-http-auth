# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sites', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='SiteAuthorizationStatus',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('require_basic_authentication', models.BooleanField(default=False, verbose_name=b'Check to add password protection to this site.')),
                ('site', models.OneToOneField(to='sites.Site')),
            ],
        ),
    ]
