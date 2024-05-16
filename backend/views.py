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


def fnlog(request, effected_user, type, remarks, reason):
    created_user = request.user if request.user.is_authenticated else None
    log = UserLog.objects.create(created_user=created_user, effected_user=effected_user, log_type=type, reason=reason, remarks=remarks)

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
                    fnlog(request, None, 'Logged_in', '', '')
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
    logged_in_user = request.user
    user_profiles = CustomUser.objects.exclude(pk=logged_in_user.pk).exclude(is_superuser=True)
    user_logs = UserLog.objects.filter(created_user=logged_in_user)
    paths = Path.objects.all().order_by("-Created_at").order_by("-id")
    roles=Role.objects.all().order_by("-Created_at").order_by("-id").order_by("role")
    context={'user_profiles':user_profiles, 'paths':paths, 'roles':roles,'user_logs':user_logs}
    return render(request, 'profile/profile.html',context)

def change_profile_image(request):
    if request.method == 'POST' and request.FILES.get('profile_img'):
        profile_img = request.FILES['profile_img']
        # Save the new profile image to the user's profile
        request.user.profile_img = profile_img
        request.user.save()
        messages.success(request, "Profile image changed successfully.")
        return JsonResponse({'url': request.user.profile_img.url})
    return JsonResponse({'error': 'Invalid request'}, status=400)

def delete_profile_image(request):
    if request.method == 'POST':
        # Delete the profile image associated with the current user
        request.user.profile_img.delete()
        messages.success(request, "Profile image deleted successfully.")
        return JsonResponse({'message': 'Profile image deleted successfully'})
    return JsonResponse({'error': 'Invalid request'}, status=400)


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
                fnlog(request,new_user,'Created_User','','')
                messages.success(request,user_add)
                return redirect("View_user")
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
    
    
    
@login_required(login_url="login")
def User_list(request,userview_id):

    if request.user.is_superuser or PermisionsOf(request,'View User').has_permission():
        context=get_menu(request)
        view_user=CustomUser.objects.get(id=userview_id)  
        user_logs=UserLog.objects.filter(created_user=view_user.id)
        context['view_user']=view_user 
        context['user_logs']=user_logs   
        return render(request,'user/view_user.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")
   
   
@login_required(login_url="login")
def Activity_logs(request):
    if request.user.is_superuser or PermisionsOf(request,'Activity Log').has_permission():
        context=get_menu(request)
        user_logs=UserLog.objects.exclude(created_user=request.user)
        context['user_logs']=user_logs
        return render(request,'user/activity_logs.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin") 
    
    
    
@login_required(login_url="login")
def Edit_user(request,useredit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit User').has_permission():
        next_url = request.GET.get('next', None)
        print('-----------',next_url)
        context=get_menu(request)
        users=CustomUser.objects.get(id=useredit_id)
        if request.method == 'POST':
            form = EditUserForm(request.POST, request.FILES, instance=users)
            if form.is_valid():
                edit_user=form.save()
                fnlog(request,edit_user,'Edited_User','','')
            
                if next_url:
                    messages.success(request,profile_edit)
                    return redirect(next_url)  # Redirect to the previous page
                else:
                    messages.success(request,user_edit)
                    return redirect("View_user")
        else:
            form = EditUserForm(instance=users)   
        
        form.fields['role'].queryset = Role.objects.filter(status='Active')
        
        context['users']=users
        context['form']=form
        if next_url:
            context['next_url']=next_url
        else:
            context['edit']=1
        
            
        return render(request,'user/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
    
def changeuserpassword(request,user_id):
    user=CustomUser.objects.get(id=user_id)
    form=ChangeUserPasswordForm(user)
    context=get_menu(request)
    if request.method=="POST":
        form=ChangeUserPasswordForm(user=user,data=request.POST )
        print(form)
        if form.is_valid():
            password=form.save()
            fnlog(request,password,'Password_changed','','')
            update_session_auth_hash(request,form.user)
            
            current_session_key = request.session.session_key
            Session.objects.filter(expire_date__gte=timezone.now(), session_key=current_session_key).exclude(session_key=current_session_key).delete()
            
            messages.success(request,password_change)
            return redirect("admin")
        else:
            print(form.errors)
            return render(request,'user/changeuserpassword.html',{'form':form})

    return render(request,'user/changeuserpassword.html',{'form':form})



@login_required(login_url="login")
def Add_path(request):
    if request.user.is_superuser or PermisionsOf(request,'Add Path').has_permission():
        context=get_menu(request)
        form=PathForm()
        form.fields['parent'].queryset = Path.objects.filter(status='Active')
        context['form']=form
        if request.method=="POST":
            form=PathForm(request.POST)

            if form.is_valid():
                form.save()
                fnlog(request,None,'Admin_and_Staff',"Add Path",'')
                messages.success(request,path_add)
                return redirect(Profile)
            else:
                context['form']=form
                return render (request,'path/add_form.html',context)
                
        return render(request,'path/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
    
@login_required(login_url="login")
def Edit_path(request,pathedit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit Path').has_permission():
        context=get_menu(request)
        paths=Path.objects.get(id=pathedit_id)
        form=PathForm(request.POST or None,instance=paths)

        if form.is_valid():
            form.save()
            fnlog(request,None,'Admin_and_Staff',"Edit Path",'')
            messages.success(request,path_edit)
            return redirect(Profile)
        
        form.fields['parent'].queryset = Path.objects.filter(status='Active')
        context['form']=form
        context['edit']=1
            
        return render(request,'path/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
    
@login_required(login_url="login")
def Add_role(request):
    if request.user.is_superuser or PermisionsOf(request,'Add Role').has_permission():
        context=get_menu(request)
        form=RoleForm()
        context['form']=form

        if request.method=="POST":
            form=RoleForm(request.POST)
            if form.is_valid():
                form.save()
                fnlog(request,None,'Admin_and_Staff',"Add Role",'')
                messages.success(request,role_add)
                return redirect(Profile)
                
            else:
                form=RoleForm()
                context['form']=form
                return render(request,'role/add_form.html',context)
                
        return render(request,'role/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")
    

@login_required(login_url="login")
def Edit_role(request,roleedit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit Role').has_permission():
        context=get_menu(request)
        roles=Role.objects.get(id=roleedit_id)
        form=RoleForm(request.POST or None,instance=roles)
        context['form']=form

        if form.is_valid():
            form.save()
            fnlog(request,None,'Admin_and_Staff',"Edit Role",'')
            messages.success(request,role_edit)
            return redirect(Profile)
            
        return render(request,'role/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")

    
    
@login_required(login_url="login")
def Add_permissions(request,perm_id):
    if request.user.is_superuser or PermisionsOf(request,'Set Permissions').has_permission():
        context=get_menu(request)
        path=Path.objects.filter(status="Active",parent=None)
        context['path']=path

        if request.method=="POST":
            perm=request.POST.getlist('sub_perm')
            mainperm=request.POST.getlist('main_perm')
            addperm=Role.objects.get(id=perm_id)
            addperm.permissions.clear()
            print( addperm.permissions)
            for i in perm:
                addperm.permissions.add(Path.objects.get(id=i))
            for j in mainperm:
                addperm.permissions.add(Path.objects.get(id=j))
            fnlog(request,None,'Admin_and_Staff',"Set Permissions",'')
            messages.success(request,permission_add)
            return redirect(Profile)

        permission=[i.id for i in  Role.objects.get(id=perm_id).permissions.all()]
        print(permission)
        context['permission']=permission

        return render(request, 'role/add_permission.html', context)
    else:
        messages.error(request,page_deny)
        return redirect("admin")