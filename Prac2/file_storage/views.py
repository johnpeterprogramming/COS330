from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseForbidden, FileResponse
from django.contrib.auth.decorators import login_required, user_passes_test, permission_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django_otp.decorators import otp_required
import os
from .models import EncryptedImage, EncryptedDocument, EncryptedConfidential
from .utils.encryption import save_encrypted_image, save_encrypted_document, get_decrypted_image, get_decrypted_document, encrypt_bytes
from .forms import RegisterForm, LoginForm, UploadImageForm, UpdateImageForm, UploadDocumentForm, UpdateDocumentForm, UpdateConfidentialForm


def login_view(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user is not None and user.is_active:
                login(request, user)
                return redirect("dashboard")
            form.add_error(None, "Inactive account.")
    else:
        form = LoginForm(request)
    return render(request, "login.html", {"form": form})

def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('login')

def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user: User = form.save(commit=False)
            user.email = form.cleaned_data["email"].lower()
            user.is_active = False  # Require admin approval
            user.save()
            return render(request, "register.html", {"form": RegisterForm(), "success": "Registration successful. Await admin approval."})
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})

def dashboard(request):
    return render(request, "dashboard.html")


# Image operations
def view_image(request, image_id):
    image: EncryptedImage = get_object_or_404(EncryptedImage, id=image_id)
    img_bytes = get_decrypted_image(image)

    return HttpResponse(img_bytes, content_type="image/jpeg")

@login_required
@otp_required
@permission_required('file_storage.delete_encryptedimage', raise_exception=True)
def delete_image(request, image_id):
    if request.method == 'POST':
        image: EncryptedImage = get_object_or_404(EncryptedImage, id=image_id)
        
        # Delete the physical file
        if os.path.exists(image.file_path):
            os.remove(image.file_path)
        
        image.delete()
        
        messages.success(request, "Image successfully deleted")
        return redirect("images")
    
    # If GET request, show confirmation page
    image = get_object_or_404(EncryptedImage, id=image_id)
    return render(request, "confirm_delete_image.html", {"image": image})


@login_required
@otp_required
@permission_required('file_storage.change_encryptedimage', raise_exception=True)
def update_image(request, image_id):
    image = get_object_or_404(EncryptedImage, id=image_id)
    
    if request.method == 'POST':
        form = UpdateImageForm(request.POST, request.FILES)
        if form.is_valid():
            # Update title
            image.title = form.cleaned_data['title']
            
            # If new image uploaded, replace the encrypted file
            if form.cleaned_data['image']:
                # Delete old file
                if os.path.exists(image.file_path):
                    os.remove(image.file_path)
                
                # Save new encrypted image
                uploaded_file = form.cleaned_data['image']
                img_bytes = uploaded_file.read()
                encrypted = encrypt_bytes(img_bytes)
                
                # Save to same path or generate new one
                folder = os.path.join(settings.MEDIA_ROOT, "images")
                os.makedirs(folder, exist_ok=True)
                filename = f"{image.title}.bin"
                file_path = os.path.join(folder, filename)
                
                with open(file_path, "wb") as f:
                    f.write(encrypted)
                
                image.file_path = file_path
            
            image.save()
            messages.success(request, "Image successfully updated")
            return redirect("images")
    else:
        # Pre-populate form with current data
        form = UpdateImageForm(initial={'title': image.title})
    
    return render(request, "update_image.html", {"form": form, "image": image})


# Document operations
@login_required
@otp_required
@permission_required('file_storage.view_encrypteddocument', raise_exception=True)
def view_document(request, document_id):
    document: EncryptedDocument = get_object_or_404(EncryptedDocument, id=document_id)
    img_bytes = get_decrypted_document(document)

    return HttpResponse(img_bytes, content_type="application/pdf")

@login_required
@otp_required
@permission_required('file_storage.delete_encrypteddocument', raise_exception=True)
def delete_document(request, document_id):
    if request.method == 'POST':
        document: EncryptedDocument = get_object_or_404(EncryptedDocument, id=document_id)
        
        # Delete the physical file
        if os.path.exists(document.file_path):
            os.remove(document.file_path)
        
        document.delete()
        
        messages.success(request, "document successfully deleted")
        return redirect("documents")
    
    # If GET request, show confirmation page
    document = get_object_or_404(EncryptedDocument, id=document_id)
    return render(request, "confirm_delete_document.html", {"document": document})


@login_required
@otp_required
@permission_required('file_storage.change_encrypteddocument', raise_exception=True)
def update_document(request, document_id):
    document = get_object_or_404(EncryptedDocument, id=document_id)
    
    if request.method == 'POST':
        if not request.user.has_perm('file_storage.change_encrypteddocument'):
            raise PermissionDenied()
        form = UpdateDocumentForm(request.POST, request.FILES)
        if form.is_valid():
            # Update title
            document.title = form.cleaned_data['title']
            
            # If new document uploaded, replace the encrypted file
            if form.cleaned_data['document']:
                # Delete old file
                if os.path.exists(document.file_path):
                    os.remove(document.file_path)
                
                # Save new encrypted document
                uploaded_file = form.cleaned_data['document']
                img_bytes = uploaded_file.read()
                encrypted = encrypt_bytes(img_bytes)
                
                # Save to same path or generate new one
                folder = os.path.join(settings.MEDIA_ROOT, "documents")
                os.makedirs(folder, exist_ok=True)
                filename = f"{document.title}.bin"
                file_path = os.path.join(folder, filename)
                
                with open(file_path, "wb") as f:
                    f.write(encrypted)
                
                document.file_path = file_path
            
            document.save()
            messages.success(request, "document successfully updated")
            return redirect("documents")
    else:
        # Pre-populate form with current data
        form = UpdateDocumentForm(initial={'title': document.title})
    
    return render(request, "update_document.html", {"form": form, "document": document})

# Confidential files
@login_required
@otp_required
@permission_required('file_storage.view_encryptedconfidential', raise_exception=True)
def update_confidential(request, confidential_id):
    confidential: EncryptedConfidential = get_object_or_404(EncryptedConfidential, id=confidential_id)
    if (request.method == "POST"):
        if not request.user.has_perm('file_storage.change_encryptedconfidential'):
            raise PermissionDenied()

        form = UpdateConfidentialForm(request.POST)
        if form.is_valid():
            confidential.title = form.cleaned_data['title']
            confidential.text = form.cleaned_data['text']
            confidential.save()

            messages.success(request, "confidentially successfully saved")
            return redirect("confidential")
    else:
        form = UpdateConfidentialForm(initial={'title': confidential.title, 'text': confidential.text})

    return render(request, "update_confidential.html", {"form": form, "confidential": confidential})

@login_required
@otp_required
@permission_required('file_storage.delete_encryptedconfidential', raise_exception=True)
def delete_confidential(request, confidential_id):
    if request.method == 'POST':
        confidential: EncryptedConfidential = get_object_or_404(EncryptedConfidential, id=confidential_id)
        confidential.delete()

        messages.success(request, "confidential was deleted successfully")
        return redirect("confidential")

    # If GET request, show confirmation page
    confidential = get_object_or_404(EncryptedConfidential, id=confidential_id)
    return render(request, "confirm_delete_confidential.html", {"confidential": confidential})

@login_required
@otp_required
@permission_required('file_storage.view_encrypteddocument', raise_exception=True)
def documents(request):
    if request.method == 'POST':
        if not request.user.has_perm('file_storage.add_encrypteddocument'):
            raise PermissionDenied()

        form = UploadDocumentForm(request.POST, request.FILES)
        if form.is_valid():
            title = form.cleaned_data['title']
            uploaded_file = form.cleaned_data['document']
            save_encrypted_document(uploaded_file, title)
            return redirect('documents')
    else:
        form = UploadDocumentForm()
    documents = EncryptedDocument.objects.all().order_by('-id')
    return render(request, "documents.html", {"documents": documents, "form": form})

@otp_required
@permission_required('file_storage.view_encryptedconfidential', raise_exception=True)
def confidential(request):
    # Create
    if request.method == 'POST':
        if not request.user.has_perm('file_storage.add_encryptedconfidential'):
            raise PermissionDenied()

        form = UpdateConfidentialForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['text']
            title = form.cleaned_data['title']
            confidential = EncryptedConfidential(title=title, text=text)
            confidential.save()

            return redirect('confidential')
    else:
        form = UpdateConfidentialForm()

    # Read
    confidentials = EncryptedConfidential.objects.all().order_by('-id')
    return render(request, "confidential.html", {"confidentials": confidentials, "form": form})

def images(request):
    if request.method == 'POST':
        if not request.user.has_perm('file_storage.add_encryptedimage'):
            raise PermissionDenied()

        form = UploadImageForm(request.POST, request.FILES)
        if form.is_valid():
            title = form.cleaned_data['title']
            uploaded_file = form.cleaned_data['image']
            save_encrypted_image(uploaded_file, title)
            return redirect('images')
    else:
        form = UploadImageForm()
    images = EncryptedImage.objects.all().order_by('-id')
    return render(request, "images.html", {"images": images, "form": form})