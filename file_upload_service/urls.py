from django.urls import path, include

urlpatterns = [
    path('',include('uploader.urls'))
]