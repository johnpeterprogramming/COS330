from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"].lower()
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    pass


class UploadImageForm(forms.Form):
    title = forms.CharField(max_length=128)
    image = forms.ImageField()


class UpdateImageForm(forms.Form):
    title = forms.CharField(max_length=128)
    image = forms.ImageField(required=False, help_text="Leave empty to keep current image")

class UploadDocumentForm(forms.Form):
    title = forms.CharField(max_length=128)
    document = forms.FileField()


class UpdateDocumentForm(forms.Form):
    title = forms.CharField(max_length=128)
    document = forms.FileField(required=False, help_text="Leave empty to keep current document")

class UpdateConfidentialForm(forms.Form):
    title = forms.CharField(max_length=128)
    text = forms.CharField(widget=forms.Textarea(attrs={'rows': 10, 'cols': 50}))