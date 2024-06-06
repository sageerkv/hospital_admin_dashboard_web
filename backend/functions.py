from logging import exception
from .models import *
# from .constants import *
from fileinput import filename
import os
import time
import pipes
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from core.settings import BASE_DIR, DATABASES
from django.shortcuts import get_object_or_404




class PermisionsOf:
    def __init__(self,request,Path):
        self.Path=Path
        self.request=request
        self.User=request.user
    def has_permission(self):
        if self.User.is_active:
            if self.User.role is not None:
                if self.Path in[i.path_name for i in self.User.role.permissions.all()]:
                    return True
                else:
                    return False
            return False

def get_menu(request):
  
    context={}

    context['is_superuser']=request.user.is_superuser
    context['is_role']=PermisionsOf(request,'View Role').has_permission()
    context['is_user']=PermisionsOf(request,'View User').has_permission()
    context['is_path']=PermisionsOf(request,'View Path').has_permission()
    context['is_account']=PermisionsOf(request,'View Bank Account').has_permission()
    context['is_patient']=PermisionsOf(request,'View Patient').has_permission()
    context['is_patient']=PermisionsOf(request,'View Payment').has_permission()
    
    return context