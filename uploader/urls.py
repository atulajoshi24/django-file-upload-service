from django.urls import path,include 
from .views import upload_file_secure, upload_file

urlpatterns = [
    path('secure-upload',upload_file_secure),
    path('upload',upload_file)
]