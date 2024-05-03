from django.urls import path,include
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    # login and home
    path('', views.index, name='admin'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    
    # profile
    path('Profile/', views.Profile, name='Profile'),
    path('change_profile_image/', views.change_profile_image, name='change_profile_image'),
    path('delete_profile_image/', views.delete_profile_image, name='delete_profile_image'),
    
    # user
    path('View_user', views.View_user, name='View_user'),
    path('Add_user/', views.Add_user, name='Add_user'),
    path('Edit_user/<useredit_id>',views.Edit_user,name="Edit_user"),
]
