from django.contrib import admin

# Register your models here.
from .models import EncryptedImage, EncryptedDocument, EncryptedConfidential    

admin.site.register(EncryptedImage)
admin.site.register(EncryptedDocument)
admin.site.register(EncryptedConfidential)