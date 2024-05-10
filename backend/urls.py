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
    path('User_list/<userview_id>',views.User_list,name="User_list"),
    # password
    path('change_user_password/<user_id>',views.changeuserpassword,name="change_user_password"),
    
    # path
    path('Add_path', views.Add_path, name='Add_path'),
    path('Edit_path/<pathedit_id>',views.Edit_path,name="Edit_path"),
    
    # role
    path('Add_role', views.Add_role, name='Add_role'),
    path('Edit_role/<roleedit_id>',views.Edit_role,name="Edit_role"),
    path('Add_permissions/<perm_id>',views.Add_permissions,name="Add_permissions"),
]
