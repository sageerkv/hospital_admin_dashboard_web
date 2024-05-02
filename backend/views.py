from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout,update_session_auth_hash
from .forms import *
from .models import *
from .functions import *
from django.db.models import Q, Sum
from django.contrib.sessions.models import Session
from datetime import datetime, timedelta
from django.core.paginator import Paginator
from django.utils import timezone
from decimal import Decimal
from django.core.exceptions import ValidationError 
from django.db import transaction
from collections import defaultdict
import json


def fnlog(request,effected_user,type,remarks,reason):
    log=UserLog(created_user=request.user,effected_user=effected_user,log_type=type,reason=reason,remarks=remarks)
    log.save()

def user_login(request):
    if request.method=="POST":

        email = request.POST.get('email')  # Used request.POST.get to safely retrieve form data
        password = request.POST.get('password')
        
        try:
            user = authenticate(email=email,password=password)
        
            if user is not None:
                if user.status == "Active":
                    user.loginAttempts = 0
                    user.save()
                    login(request, user)
                    fnlog(request, '', 'Logged_in', '', '')
                    print(user.role)
                    messages.success(request,'Login successfully.')
                    return redirect("admin")

                else:
                    messages.error(request, 'Sorry,Your Account is locked,Please contact Admin')
                    return render(request, 'auth/login.html')


            else:
                user=CustomUser.objects.get(email=email)
                if user:
                    user.loginAttempts += 1
                    user.save()
                    if user.loginAttempts >= 10:
                        user.status = "Inactive"
                        user.save()
                        fnlog(request, user, 'Deactivated', '', 'more than 5 invalid password tries')
                        messages.error(request, 'Sorry, Account Locked')
                        return render(request, 'auth/login.html')
                    else:
                        messages.error(request, 'Invalid Username or Password')
                        return render(request,'auth/login.html')
                else:
                    messages.error(request, 'Invalid username or password')
                    return render(request, 'auth/login.html')
        except:
            messages.error(request, 'Invalid username or password')
            return render(request, 'auth/login.html')

    return render(request,'auth/login.html')


@login_required(login_url="login")
def user_logout(request):
    logout(request)
    messages.success(request, ("Successfully logged out..."))
    return redirect('login')


@login_required(login_url="login")
def Profile(request):
    return render(request, 'profile/profile.html')


@login_required(login_url="login")
def index(request):
    return render(request, 'index.html')


@login_required(login_url="login")
def View_user(request):
    if request.user.is_superuser or PermisionsOf(request,'View User').has_permission():
        context=get_menu(request)
        users=CustomUser.objects.all().exclude(Q(is_superuser=1)).order_by("-Created_at").order_by("-id")
        roles = Role.objects.all().order_by("role")
        context['roles'] = roles
        if request.method=="GET":
            name=request.GET.get('name')
            roles_id = request.GET.get('role')
            status=request.GET.get('status')

            if name:
                users=users.filter(first_name__icontains=name)
            
            if roles_id:
                users = users.filter(role_id=roles_id)
            
            if status:
                users = users.filter(status__iexact=status.capitalize())

        # paginator=Paginator(users,20)
        # page_num=request.GET.get('page')
        # users_page = paginator.get_page(page_num)
        context['users'] = users

        return render(request,'user/form_data.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
    
@login_required(login_url="login")
def Add_user(request):
    if request.user.is_superuser or PermisionsOf(request,'Add User').has_permission():
        context=get_menu(request)
        form=CustomUserForm()
        context['form']=form
        if request.method=="POST":
            form=CustomUserForm(request.POST)   
            if form.is_valid():
                new_user=form.save()
                fnlog(request,new_user.id,'Created_User','','')
                messages.success(request,user_add)
                return redirect(index)
            else:
                print(form.errors)
                context['form']=form
        
        else:
            form = CustomUserForm()
            form.fields['role'].queryset = Role.objects.filter(status='Active')
            context['form'] = form
            
        return render (request,'user/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")