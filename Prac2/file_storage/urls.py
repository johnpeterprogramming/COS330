from django.urls import path

from . import views

urlpatterns = [
    # Remove custom login/logout, using 2FA instead
    # path('login/', views.login_view, name='login'),
    # path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('', views.dashboard, name='dashboard'),

    path('images/<int:image_id>/delete', views.delete_image, name='delete_image'),
    path('images/<int:image_id>/update', views.update_image, name='update_image'),
    path('images/<int:image_id>/', views.view_image, name='view_image'),
    path('images/', views.images, name='images'),

    path('documents/<int:document_id>/delete', views.delete_document, name='delete_document'),
    path('documents/<int:document_id>/update', views.update_document, name='update_document'),
    path('documents/<int:document_id>/', views.view_document, name='view_document'),
    path('documents/', views.documents, name='documents'),

    path('confidential/<int:confidential_id>/delete', views.delete_confidential, name='delete_confidential'),
    path('confidential/<int:confidential_id>/update', views.update_confidential, name='update_confidential'),
    path('confidential/', views.confidential, name='confidential'),
]