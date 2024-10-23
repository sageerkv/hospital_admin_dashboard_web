from django.urls import path,include
from . import views
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView

urlpatterns = [
    # login and home
    path('', views.index, name='admin'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    
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
    # activity_logs
    path('Activity_logs', views.Activity_logs, name='Activity_logs'),
    
    # path
    path('Add_path', views.Add_path, name='Add_path'),
    path('Edit_path/<pathedit_id>',views.Edit_path,name="Edit_path"),
    
    # role
    path('Add_role', views.Add_role, name='Add_role'),
    path('Edit_role/<roleedit_id>',views.Edit_role,name="Edit_role"),
    path('Add_permissions/<perm_id>',views.Add_permissions,name="Add_permissions"),
    
    # site_settings
    path('site_settings',views.site_settings, name="site_settings"),
    path('add_site_settings',views.add_site_settings, name="add_site_settings"),
    path('edit_site_settings/<int:site_settingsedit_id>',views.edit_site_settings, name="edit_site_settings"),
    
    # bank accounts
    path('View_account', views.View_account, name='View_account'),
    path('Add_account', views.Add_account, name='Add_account'),
    path('Edit_account/<accountedit_id>',views.Edit_account,name="Edit_account"),
    
    # patient and client
    path('View_patient', views.View_patient, name='View_patient'),
    path('Add_patient', views.Add_patient, name='Add_patient'),
    path('Edit_patient/<patientedit_id>',views.Edit_patient,name="Edit_patient"),
    path('Patient_list/<int:patientview_id>/', views.Patient_list, name="Patient_list"),
    path('Patient_list/<int:patientview_id>/transaction/<int:transaction_id>/', views.transaction_detail, name="transaction_detail"),
    path('patient/<int:patientview_id>/make_payment/<int:transaction_id>/', views.make_payment, name='make_payment'),
]
