import base64
import types
from django import forms

from django.db import models
from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from Crypto.Cipher import AES
from Crypto import Random


class BaseEncryptedField(models.Field):
    """
    an encrypted string field for password or security key
    """
    description = _("An encrypted string")
    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        self.prefix = kwargs.pop('prefix', '_')
        super(BaseEncryptedField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return 'TextField'

    def _pad(self, s, block_size=AES.block_size):
        return s + (block_size - len(s) %block_size) * chr(block_size - len(s) % block_size)

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def _is_encrypted(self, value):
        return isinstance(value, basestring) and value.startswith(self.prefix)

    def get_db_prep_value(self, value, connection=None, prepared=False):
        if value is not None and not self._is_encrypted(value):
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(settings.FIELD_ENCRYPTION_KEY[:32], AES.MODE_CBC, iv)
            value = self._pad(value, AES.block_size)
            value = self.prefix + base64.b64encode(iv + cipher.encrypt(value))
        return value

    def get_db_prep_save(self, value, connection=None):
        return self.get_db_prep_value(value, connection=connection)

    def to_python(self, value):
        print 'call to python'
        if value is None or not isinstance(value, types.StringTypes):
            return value

        if self._is_encrypted(value):
            value = value[len(self.prefix):]  # cut prefix
            value = base64.b64decode(value)
            iv, encrypted = value[:AES.block_size], value[AES.block_size:]  # extract iv

            cipher = AES.new(settings.FIELD_ENCRYPTION_KEY[:32], AES.MODE_CBC, iv)
            value = self._unpad(cipher.decrypt(value[AES.block_size:])).decode('utf-8')
        return value


class EncryptedTextField(BaseEncryptedField):
    def get_internal_type(self):
        return 'TextField'

    def formfield(self, **kwargs):
        defaults = {'widget': forms.Textarea}
        defaults.update(kwargs)
        return super(EncryptedTextField, self).formfield(**defaults)


class EncryptedCharField(BaseEncryptedField):

    def get_internal_type(self):
        return "CharField"

    def formfield(self, **kwargs):
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super(EncryptedCharField, self).formfield(**defaults)
