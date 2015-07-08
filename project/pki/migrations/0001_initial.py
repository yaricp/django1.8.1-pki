# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import project.pki.models
from django.conf import settings
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('description', models.CharField(max_length=255)),
                ('country', models.CharField(default=b'RU', max_length=2, choices=[(b'AD', b'AD'), (b'AE', b'AE'), (b'AF', b'AF'), (b'AG', b'AG'), (b'AI', b'AI'), (b'AL', b'AL'), (b'AM', b'AM'), (b'AN', b'AN'), (b'AO', b'AO'), (b'AQ', b'AQ'), (b'AR', b'AR'), (b'AS', b'AS'), (b'AT', b'AT'), (b'AU', b'AU'), (b'AW', b'AW'), (b'AZ', b'AZ'), (b'BA', b'BA'), (b'BB', b'BB'), (b'BD', b'BD'), (b'BE', b'BE'), (b'BF', b'BF'), (b'BG', b'BG'), (b'BH', b'BH'), (b'BI', b'BI'), (b'BJ', b'BJ'), (b'BM', b'BM'), (b'BN', b'BN'), (b'BO', b'BO'), (b'BR', b'BR'), (b'BS', b'BS'), (b'BT', b'BT'), (b'BU', b'BU'), (b'BV', b'BV'), (b'BW', b'BW'), (b'BY', b'BY'), (b'BZ', b'BZ'), (b'CA', b'CA'), (b'CC', b'CC'), (b'CF', b'CF'), (b'CG', b'CG'), (b'CH', b'CH'), (b'CI', b'CI'), (b'CK', b'CK'), (b'CL', b'CL'), (b'CM', b'CM'), (b'CN', b'CN'), (b'CO', b'CO'), (b'CR', b'CR'), (b'CS', b'CS'), (b'CU', b'CU'), (b'CV', b'CV'), (b'CX', b'CX'), (b'CY', b'CY'), (b'CZ', b'CZ'), (b'DD', b'DD'), (b'DE', b'DE'), (b'DJ', b'DJ'), (b'DK', b'DK'), (b'DM', b'DM'), (b'DO', b'DO'), (b'DZ', b'DZ'), (b'EC', b'EC'), (b'EE', b'EE'), (b'EG', b'EG'), (b'EH', b'EH'), (b'ER', b'ER'), (b'ES', b'ES'), (b'ET', b'ET'), (b'FI', b'FI'), (b'FJ', b'FJ'), (b'FK', b'FK'), (b'FM', b'FM'), (b'FO', b'FO'), (b'FR', b'FR'), (b'FX', b'FX'), (b'GA', b'GA'), (b'GB', b'GB'), (b'GD', b'GD'), (b'GE', b'GE'), (b'GF', b'GF'), (b'GH', b'GH'), (b'GI', b'GI'), (b'GL', b'GL'), (b'GM', b'GM'), (b'GN', b'GN'), (b'GP', b'GP'), (b'GQ', b'GQ'), (b'GR', b'GR'), (b'GS', b'GS'), (b'GT', b'GT'), (b'GU', b'GU'), (b'GW', b'GW'), (b'GY', b'GY'), (b'HK', b'HK'), (b'HM', b'HM'), (b'HN', b'HN'), (b'HR', b'HR'), (b'HT', b'HT'), (b'HU', b'HU'), (b'ID', b'ID'), (b'IE', b'IE'), (b'IL', b'IL'), (b'IN', b'IN'), (b'IO', b'IO'), (b'IQ', b'IQ'), (b'IR', b'IR'), (b'IS', b'IS'), (b'IT', b'IT'), (b'JM', b'JM'), (b'JO', b'JO'), (b'JP', b'JP'), (b'KE', b'KE'), (b'KG', b'KG'), (b'KH', b'KH'), (b'KI', b'KI'), (b'KM', b'KM'), (b'KN', b'KN'), (b'KP', b'KP'), (b'KR', b'KR'), (b'KW', b'KW'), (b'KY', b'KY'), (b'KZ', b'KZ'), (b'LA', b'LA'), (b'LB', b'LB'), (b'LC', b'LC'), (b'LI', b'LI'), (b'LK', b'LK'), (b'LR', b'LR'), (b'LS', b'LS'), (b'LT', b'LT'), (b'LU', b'LU'), (b'LV', b'LV'), (b'LY', b'LY'), (b'MA', b'MA'), (b'MC', b'MC'), (b'MD', b'MD'), (b'MG', b'MG'), (b'MH', b'MH'), (b'ML', b'ML'), (b'MM', b'MM'), (b'MN', b'MN'), (b'MO', b'MO'), (b'MP', b'MP'), (b'MQ', b'MQ'), (b'MR', b'MR'), (b'MS', b'MS'), (b'MT', b'MT'), (b'MU', b'MU'), (b'MV', b'MV'), (b'MW', b'MW'), (b'MX', b'MX'), (b'MY', b'MY'), (b'MZ', b'MZ'), (b'NA', b'NA'), (b'NC', b'NC'), (b'NE', b'NE'), (b'NF', b'NF'), (b'NG', b'NG'), (b'NI', b'NI'), (b'NL', b'NL'), (b'NO', b'NO'), (b'NP', b'NP'), (b'NR', b'NR'), (b'NT', b'NT'), (b'NU', b'NU'), (b'NZ', b'NZ'), (b'OM', b'OM'), (b'PA', b'PA'), (b'PE', b'PE'), (b'PF', b'PF'), (b'PG', b'PG'), (b'PH', b'PH'), (b'PK', b'PK'), (b'PL', b'PL'), (b'PM', b'PM'), (b'PN', b'PN'), (b'PR', b'PR'), (b'PT', b'PT'), (b'PW', b'PW'), (b'PY', b'PY'), (b'QA', b'QA'), (b'RE', b'RE'), (b'RO', b'RO'), (b'RU', b'RU'), (b'RW', b'RW'), (b'SA', b'SA'), (b'SB', b'SB'), (b'SC', b'SC'), (b'SD', b'SD'), (b'SE', b'SE'), (b'SG', b'SG'), (b'SH', b'SH'), (b'SI', b'SI'), (b'SJ', b'SJ'), (b'SK', b'SK'), (b'SL', b'SL'), (b'SM', b'SM'), (b'SN', b'SN'), (b'SO', b'SO'), (b'SR', b'SR'), (b'ST', b'ST'), (b'SU', b'SU'), (b'SV', b'SV'), (b'SY', b'SY'), (b'SZ', b'SZ'), (b'TC', b'TC'), (b'TD', b'TD'), (b'TF', b'TF'), (b'TG', b'TG'), (b'TH', b'TH'), (b'TJ', b'TJ'), (b'TK', b'TK'), (b'TM', b'TM'), (b'TN', b'TN'), (b'TO', b'TO'), (b'TP', b'TP'), (b'TR', b'TR'), (b'TT', b'TT'), (b'TV', b'TV'), (b'TW', b'TW'), (b'TZ', b'TZ'), (b'UA', b'UA'), (b'UG', b'UG'), (b'UM', b'UM'), (b'US', b'US'), (b'UY', b'UY'), (b'UZ', b'UZ'), (b'VA', b'VA'), (b'VC', b'VC'), (b'VE', b'VE'), (b'VG', b'VG'), (b'VI', b'VI'), (b'VN', b'VN'), (b'VU', b'VU'), (b'WF', b'WF'), (b'WS', b'WS'), (b'YD', b'YD'), (b'YE', b'YE'), (b'YT', b'YT'), (b'YU', b'YU'), (b'ZA', b'ZA'), (b'ZM', b'ZM'), (b'ZR', b'ZR'), (b'ZW', b'ZW'), (b'ZZ', b'ZZ'), (b'ZZ', b'ZZ')])),
                ('state', models.CharField(max_length=32)),
                ('locality', models.CharField(max_length=32)),
                ('organization', models.CharField(max_length=64)),
                ('OU', models.CharField(max_length=64, null=True, blank=True)),
                ('email', models.EmailField(max_length=254, null=True, blank=True)),
                ('valid_days', models.IntegerField(validators=[django.core.validators.MinValueValidator(1)])),
                ('key_length', models.IntegerField(default=2048, choices=[(1024, b'1024'), (2048, b'2048'), (4096, b'4096')])),
                ('expiry_date', models.DateField(null=True, blank=True)),
                ('created', models.DateTimeField(null=True, blank=True)),
                ('revoked', models.DateTimeField(null=True, blank=True)),
                ('active', models.BooleanField(default=True, help_text=b'Turn off to revoke this certificate')),
                ('serial', models.CharField(max_length=64, null=True, blank=True)),
                ('ca_chain', models.CharField(max_length=200, null=True, blank=True)),
                ('der_encoded', models.BooleanField(default=False, verbose_name=b'DER encoding')),
                ('action', models.CharField(default=b'create', help_text=b'Yellow fields can/have to be modified!', max_length=32, choices=[(b'create', b'Create certificate'), (b'update', b'Update description and export options'), (b'revoke', b'Revoke certificate'), (b'renew', b'Renew CSR (CN and key are kept)')])),
                ('crl_dpoints', models.CharField(validators=[project.pki.models.validate_crl_dp], max_length=255, blank=True, help_text=b'Comma seperated list of URI elements. Example: URI:http://ca.local/ca.crl,...', null=True, verbose_name=b'CRL Distribution Points')),
                ('common_name', models.CharField(max_length=64)),
                ('name', models.CharField(help_text=b"Only change the suggestion if you really know what you're doing", max_length=64, validators=[django.core.validators.RegexValidator(b'[a-zA-Z0-9-_\\.]+', message=b'Name may only contain characters in range a-Z0-9_-.')])),
                ('passphrase', models.CharField(blank=True, max_length=255, null=True, validators=[django.core.validators.MinLengthValidator(7)])),
                ('parent_passphrase', models.CharField(max_length=255, null=True, blank=True)),
                ('pkcs12_encoded', models.BooleanField(default=False, verbose_name=b'PKCS#12 encoding')),
                ('pkcs12_passphrase', models.CharField(blank=True, max_length=255, null=True, verbose_name=b'PKCS#12 passphrase', validators=[django.core.validators.MinLengthValidator(8)])),
                ('subjaltname', models.CharField(validators=[project.pki.models.validate_subject_altname], max_length=255, blank=True, help_text=b'Comma seperated list of alt names. Valid are DNS:www.xyz.com, IP:1.2.3.4 and email:a@b.com in any                                          combination. Refer to the official openssl documentation for details', null=True, verbose_name=b'SubjectAltName')),
            ],
            options={
                'db_table': 'pki_certificate',
                'verbose_name_plural': 'Certificates',
                'permissions': (('can_download', 'Can download'),),
            },
        ),
        migrations.CreateModel(
            name='CertificateAuthority',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('description', models.CharField(max_length=255)),
                ('country', models.CharField(default=b'RU', max_length=2, choices=[(b'AD', b'AD'), (b'AE', b'AE'), (b'AF', b'AF'), (b'AG', b'AG'), (b'AI', b'AI'), (b'AL', b'AL'), (b'AM', b'AM'), (b'AN', b'AN'), (b'AO', b'AO'), (b'AQ', b'AQ'), (b'AR', b'AR'), (b'AS', b'AS'), (b'AT', b'AT'), (b'AU', b'AU'), (b'AW', b'AW'), (b'AZ', b'AZ'), (b'BA', b'BA'), (b'BB', b'BB'), (b'BD', b'BD'), (b'BE', b'BE'), (b'BF', b'BF'), (b'BG', b'BG'), (b'BH', b'BH'), (b'BI', b'BI'), (b'BJ', b'BJ'), (b'BM', b'BM'), (b'BN', b'BN'), (b'BO', b'BO'), (b'BR', b'BR'), (b'BS', b'BS'), (b'BT', b'BT'), (b'BU', b'BU'), (b'BV', b'BV'), (b'BW', b'BW'), (b'BY', b'BY'), (b'BZ', b'BZ'), (b'CA', b'CA'), (b'CC', b'CC'), (b'CF', b'CF'), (b'CG', b'CG'), (b'CH', b'CH'), (b'CI', b'CI'), (b'CK', b'CK'), (b'CL', b'CL'), (b'CM', b'CM'), (b'CN', b'CN'), (b'CO', b'CO'), (b'CR', b'CR'), (b'CS', b'CS'), (b'CU', b'CU'), (b'CV', b'CV'), (b'CX', b'CX'), (b'CY', b'CY'), (b'CZ', b'CZ'), (b'DD', b'DD'), (b'DE', b'DE'), (b'DJ', b'DJ'), (b'DK', b'DK'), (b'DM', b'DM'), (b'DO', b'DO'), (b'DZ', b'DZ'), (b'EC', b'EC'), (b'EE', b'EE'), (b'EG', b'EG'), (b'EH', b'EH'), (b'ER', b'ER'), (b'ES', b'ES'), (b'ET', b'ET'), (b'FI', b'FI'), (b'FJ', b'FJ'), (b'FK', b'FK'), (b'FM', b'FM'), (b'FO', b'FO'), (b'FR', b'FR'), (b'FX', b'FX'), (b'GA', b'GA'), (b'GB', b'GB'), (b'GD', b'GD'), (b'GE', b'GE'), (b'GF', b'GF'), (b'GH', b'GH'), (b'GI', b'GI'), (b'GL', b'GL'), (b'GM', b'GM'), (b'GN', b'GN'), (b'GP', b'GP'), (b'GQ', b'GQ'), (b'GR', b'GR'), (b'GS', b'GS'), (b'GT', b'GT'), (b'GU', b'GU'), (b'GW', b'GW'), (b'GY', b'GY'), (b'HK', b'HK'), (b'HM', b'HM'), (b'HN', b'HN'), (b'HR', b'HR'), (b'HT', b'HT'), (b'HU', b'HU'), (b'ID', b'ID'), (b'IE', b'IE'), (b'IL', b'IL'), (b'IN', b'IN'), (b'IO', b'IO'), (b'IQ', b'IQ'), (b'IR', b'IR'), (b'IS', b'IS'), (b'IT', b'IT'), (b'JM', b'JM'), (b'JO', b'JO'), (b'JP', b'JP'), (b'KE', b'KE'), (b'KG', b'KG'), (b'KH', b'KH'), (b'KI', b'KI'), (b'KM', b'KM'), (b'KN', b'KN'), (b'KP', b'KP'), (b'KR', b'KR'), (b'KW', b'KW'), (b'KY', b'KY'), (b'KZ', b'KZ'), (b'LA', b'LA'), (b'LB', b'LB'), (b'LC', b'LC'), (b'LI', b'LI'), (b'LK', b'LK'), (b'LR', b'LR'), (b'LS', b'LS'), (b'LT', b'LT'), (b'LU', b'LU'), (b'LV', b'LV'), (b'LY', b'LY'), (b'MA', b'MA'), (b'MC', b'MC'), (b'MD', b'MD'), (b'MG', b'MG'), (b'MH', b'MH'), (b'ML', b'ML'), (b'MM', b'MM'), (b'MN', b'MN'), (b'MO', b'MO'), (b'MP', b'MP'), (b'MQ', b'MQ'), (b'MR', b'MR'), (b'MS', b'MS'), (b'MT', b'MT'), (b'MU', b'MU'), (b'MV', b'MV'), (b'MW', b'MW'), (b'MX', b'MX'), (b'MY', b'MY'), (b'MZ', b'MZ'), (b'NA', b'NA'), (b'NC', b'NC'), (b'NE', b'NE'), (b'NF', b'NF'), (b'NG', b'NG'), (b'NI', b'NI'), (b'NL', b'NL'), (b'NO', b'NO'), (b'NP', b'NP'), (b'NR', b'NR'), (b'NT', b'NT'), (b'NU', b'NU'), (b'NZ', b'NZ'), (b'OM', b'OM'), (b'PA', b'PA'), (b'PE', b'PE'), (b'PF', b'PF'), (b'PG', b'PG'), (b'PH', b'PH'), (b'PK', b'PK'), (b'PL', b'PL'), (b'PM', b'PM'), (b'PN', b'PN'), (b'PR', b'PR'), (b'PT', b'PT'), (b'PW', b'PW'), (b'PY', b'PY'), (b'QA', b'QA'), (b'RE', b'RE'), (b'RO', b'RO'), (b'RU', b'RU'), (b'RW', b'RW'), (b'SA', b'SA'), (b'SB', b'SB'), (b'SC', b'SC'), (b'SD', b'SD'), (b'SE', b'SE'), (b'SG', b'SG'), (b'SH', b'SH'), (b'SI', b'SI'), (b'SJ', b'SJ'), (b'SK', b'SK'), (b'SL', b'SL'), (b'SM', b'SM'), (b'SN', b'SN'), (b'SO', b'SO'), (b'SR', b'SR'), (b'ST', b'ST'), (b'SU', b'SU'), (b'SV', b'SV'), (b'SY', b'SY'), (b'SZ', b'SZ'), (b'TC', b'TC'), (b'TD', b'TD'), (b'TF', b'TF'), (b'TG', b'TG'), (b'TH', b'TH'), (b'TJ', b'TJ'), (b'TK', b'TK'), (b'TM', b'TM'), (b'TN', b'TN'), (b'TO', b'TO'), (b'TP', b'TP'), (b'TR', b'TR'), (b'TT', b'TT'), (b'TV', b'TV'), (b'TW', b'TW'), (b'TZ', b'TZ'), (b'UA', b'UA'), (b'UG', b'UG'), (b'UM', b'UM'), (b'US', b'US'), (b'UY', b'UY'), (b'UZ', b'UZ'), (b'VA', b'VA'), (b'VC', b'VC'), (b'VE', b'VE'), (b'VG', b'VG'), (b'VI', b'VI'), (b'VN', b'VN'), (b'VU', b'VU'), (b'WF', b'WF'), (b'WS', b'WS'), (b'YD', b'YD'), (b'YE', b'YE'), (b'YT', b'YT'), (b'YU', b'YU'), (b'ZA', b'ZA'), (b'ZM', b'ZM'), (b'ZR', b'ZR'), (b'ZW', b'ZW'), (b'ZZ', b'ZZ'), (b'ZZ', b'ZZ')])),
                ('state', models.CharField(max_length=32)),
                ('locality', models.CharField(max_length=32)),
                ('organization', models.CharField(max_length=64)),
                ('OU', models.CharField(max_length=64, null=True, blank=True)),
                ('email', models.EmailField(max_length=254, null=True, blank=True)),
                ('valid_days', models.IntegerField(validators=[django.core.validators.MinValueValidator(1)])),
                ('key_length', models.IntegerField(default=2048, choices=[(1024, b'1024'), (2048, b'2048'), (4096, b'4096')])),
                ('expiry_date', models.DateField(null=True, blank=True)),
                ('created', models.DateTimeField(null=True, blank=True)),
                ('revoked', models.DateTimeField(null=True, blank=True)),
                ('active', models.BooleanField(default=True, help_text=b'Turn off to revoke this certificate')),
                ('serial', models.CharField(max_length=64, null=True, blank=True)),
                ('ca_chain', models.CharField(max_length=200, null=True, blank=True)),
                ('der_encoded', models.BooleanField(default=False, verbose_name=b'DER encoding')),
                ('action', models.CharField(default=b'create', help_text=b'Yellow fields can/have to be modified!', max_length=32, choices=[(b'create', b'Create certificate'), (b'update', b'Update description and export options'), (b'revoke', b'Revoke certificate'), (b'renew', b'Renew CSR (CN and key are kept)')])),
                ('crl_dpoints', models.CharField(validators=[project.pki.models.validate_crl_dp], max_length=255, blank=True, help_text=b'Comma seperated list of URI elements. Example: URI:http://ca.local/ca.crl,...', null=True, verbose_name=b'CRL Distribution Points')),
                ('common_name', models.CharField(unique=True, max_length=64)),
                ('name', models.CharField(help_text=b"Only change the suggestion if you really know what you're doing", unique=True, max_length=64, validators=[django.core.validators.RegexValidator(b'[a-zA-Z0-9-_\\.]+', message=b'Name may only contain characters in range a-Z0-9_-.')])),
                ('passphrase', models.CharField(blank=True, help_text=b"At least 8 characters. Remeber this passphrase - <font color='red'>                                                                     <strong>IT'S NOT RECOVERABLE</strong></font><br>Will be shown as md5 encrypted string", max_length=255, validators=[django.core.validators.MinLengthValidator(7)])),
                ('parent_passphrase', models.CharField(help_text=b'Leave empty if this is a top-level CA', max_length=255, null=True, blank=True)),
                ('policy', models.CharField(default=b'policy_anything', help_text=b'policy_match: All subject settings must                                                                     match the signing CA<br>                                                                     policy_anything: Nothing has to match the                                                                     signing CA', max_length=50, choices=[(b'policy_match', b'policy_match'), (b'policy_anything', b'policy_anything')])),
            ],
            options={
                'db_table': 'pki_certificateauthority',
                'verbose_name_plural': 'Certificate Authorities',
                'permissions': (('can_download', 'Can download'),),
            },
        ),
        migrations.CreateModel(
            name='ExtendedKeyUsage',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=64)),
            ],
        ),
        migrations.CreateModel(
            name='KeyUsage',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=64)),
            ],
        ),
        migrations.CreateModel(
            name='PkiChangelog',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('model_id', models.IntegerField()),
                ('object_id', models.IntegerField()),
                ('action_time', models.DateTimeField(auto_now=True)),
                ('action', models.CharField(max_length=64)),
                ('changes', models.TextField()),
                ('user', models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
                'ordering': ['-action_time'],
                'db_table': 'pki_changelog',
            },
        ),
        migrations.CreateModel(
            name='x509Extension',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=255, validators=[django.core.validators.RegexValidator(b'[a-zA-Z0-9-_\\.]+', message=b'Name may only contain characters in range a-Z0-9_-.')])),
                ('description', models.CharField(max_length=255)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('basic_constraints', models.CharField(max_length=255, verbose_name=b'basicConstraints', choices=[(b'CA:TRUE', b'Root or Intermediate CA (CA:TRUE)'), (b'CA:TRUE,pathlen:0', b'Edge CA (CA:TRUE, pathlen:0)'), (b'CA:FALSE', b'Enduser Certificate (CA:FALSE)')])),
                ('basic_constraints_critical', models.BooleanField(default=True, verbose_name=b'Make basicConstraints critical')),
                ('key_usage_critical', models.BooleanField(verbose_name=b'Make keyUsage critical')),
                ('extended_key_usage_critical', models.BooleanField(verbose_name=b'Make extendedKeyUsage critical')),
                ('subject_key_identifier', models.CharField(default=b'hash', max_length=255, verbose_name=b'subjectKeyIdentifier', choices=[(b'hash', b'hash')])),
                ('authority_key_identifier', models.CharField(default=b'keyid:always,issuer:always', max_length=255, verbose_name=b'authorityKeyIdentifier', choices=[(b'keyid:always,issuer:always', b'keyid: always, issuer: always')])),
                ('crl_distribution_point', models.BooleanField(help_text=b'All objects using this x509 extension will require a CRLDistributionPoint', verbose_name=b'Require CRL Distribution Point')),
                ('extended_key_usage', models.ManyToManyField(help_text=b'serverAuth - SSL/TLS Web Server Authentication<br />                                                                     clientAuth - SSL/TLS Web Client Authentication.<br />                                                                     codeSigning - Code signing<br />                                                                     emailProtection - E-mail Protection (S/MIME)<br />                                                                     timeStamping - Trusted Timestamping<br />                                                                     msCodeInd - Microsoft Individual Code Signing (authenticode)<br />                                                                     msCodeCom - Microsoft Commercial Code Signing (authenticode)<br />                                                                     msCTLSign - Microsoft Trust List Signing<br />                                                                     msSGC - Microsoft Server Gated Crypto<br />                                                                     msEFS - Microsoft Encrypted File System<br />                                                                     nsSGC - Netscape Server Gated Crypto<br />', to='pki.ExtendedKeyUsage', null=True, verbose_name=b'extendedKeyUsage', blank=True)),
                ('key_usage', models.ManyToManyField(help_text=b'Usual values:<br />                                                                    CA: keyCertSign, cRLsign<br />                                                                    Cert: digitalSignature, nonRedupiation, keyEncipherment<br />', to='pki.KeyUsage', verbose_name=b'keyUsage')),
            ],
            options={
                'db_table': 'pki_x509extension',
            },
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='extension',
            field=models.ForeignKey(verbose_name=b'x509 Extension', blank=True, to='pki.x509Extension', null=True),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='parent',
            field=models.ForeignKey(blank=True, to='pki.CertificateAuthority', null=True),
        ),
        migrations.AddField(
            model_name='certificate',
            name='extension',
            field=models.ForeignKey(verbose_name=b'x509 Extension', blank=True, to='pki.x509Extension', null=True),
        ),
        migrations.AddField(
            model_name='certificate',
            name='parent',
            field=models.ForeignKey(blank=True, to='pki.CertificateAuthority', help_text=b'Leave blank to generate self-signed certificate', null=True),
        ),
        migrations.AlterUniqueTogether(
            name='certificate',
            unique_together=set([('name', 'parent'), ('common_name', 'parent')]),
        ),
    ]
