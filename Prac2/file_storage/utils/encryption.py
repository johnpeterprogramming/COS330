import os
from cryptography.fernet import Fernet
from ..models import EncryptedImage, EncryptedDocument
from django.conf import settings

fernet = Fernet(settings.FERNET_KEY.encode())

def encrypt_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_bytes(data: bytes) -> bytes:
    return fernet.decrypt(data)

    
def save_encrypted_file(uploaded_file, title, directory):
    # Read bytes from UploadedFile
    img_bytes = uploaded_file.read()
    encrypted = encrypt_bytes(img_bytes)

    folder = os.path.join(settings.MEDIA_ROOT, directory)
    os.makedirs(folder, exist_ok=True)

    filename = f"{title}.bin"
    file_path = os.path.join(folder, filename)

    with open(file_path, "wb") as f:
        f.write(encrypted)
    
    return file_path

def save_encrypted_image(uploaded_file, title):
    file_path = save_encrypted_file(uploaded_file, title, "images")

    return EncryptedImage.objects.create(title=title, file_path=file_path)

def save_encrypted_document(uploaded_file, title):
    file_path = save_encrypted_file(uploaded_file, title, "documents")

    return EncryptedDocument.objects.create(title=title, file_path=file_path)


def get_decrypted_image(image: EncryptedImage):
    with open(image.file_path, "rb") as f:
        encrypted = f.read()

    img_bytes = decrypt_bytes(encrypted)

    return img_bytes

def get_decrypted_document(document: EncryptedDocument):
    with open(document.file_path, "rb") as f:
        encrypted = f.read()

    doc_bytes = decrypt_bytes(encrypted)

    return doc_bytes