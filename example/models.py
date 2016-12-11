from db.models.fields.encryption import BaseEncryptedField, EncryptedCharField
from django.db import models

# Create your models here.


class Example(models.Model):
    secret = EncryptedCharField(max_length=16)

    class Meta:
        ordering = ('secret',)