from django.db import models
from encrypted_model_fields.fields import EncryptedTextField


class EncryptedImage(models.Model):
    title = models.CharField(max_length=128)
    file_path = models.CharField(max_length=256)

    def __str__(self):
        return "Image " + self.title

class EncryptedDocument(models.Model):
    title = models.CharField(max_length=128)
    file_path = models.CharField(max_length=256)

    def __str__(self):
        return "Document " + self.title

class EncryptedConfidential(models.Model):
    title = models.CharField(max_length=128)
    text = EncryptedTextField()