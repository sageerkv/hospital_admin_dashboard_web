from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
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
from django.urls import reverse
import decimal

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


# profile
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
    context = get_menu(request)
    
    all_patient = Patient_And_Client.objects.all().count()
    # Get the current month and year
    current_month = datetime.now().month
    current_year = datetime.now().year
    current_day = datetime.now().day
    
    day_transactions = Payment.objects.filter(Updated_at__day=current_day)
    day_totals = day_transactions.aggregate(
        total_amount=Sum('amount'),
        total_discount=Sum('discount_amount')
    )
    total_day_earnings = (day_totals['total_amount'] or 0) - (day_totals['total_discount'] or 0)
    
    # Filter all transactions by the current month
    monthly_transactions = Transactions.objects.filter(Updated_at__month=current_month, Updated_at__year=current_year)
    
    # Calculate the total earnings for the current month
    monthly_totals = monthly_transactions.aggregate(
        total_amount=Sum('Total_amount'),
        total_discount=Sum('Discount')
    )
    total_monthly_earnings = (monthly_totals['total_amount'] or 0) - (monthly_totals['total_discount'] or 0)
    
     # Filter all transactions by the current month
    yearly_transactions = Transactions.objects.filter(Updated_at__year=current_year)
    
    # Calculate the total earnings for the current month
    yearly_totals = yearly_transactions.aggregate(
        total_amount=Sum('Total_amount'),
        total_discount=Sum('Discount')
    )
    total_yearly_earnings = (yearly_totals['total_amount'] or 0) - (yearly_totals['total_discount'] or 0)
    
    
    # chart calculation total amount earned
    monthly_chart_totals = []
    for month in range(1, 13):
        monthly_chart_transactions = Transactions.objects.filter(Updated_at__year=current_year, Updated_at__month=month)
        totals = monthly_chart_transactions.aggregate(
            total_amount=Sum('Total_amount'),
            total_discount=Sum('Discount')
        )
        total_chart_earnings = float((totals['total_amount'] or 0) - (totals['total_discount'] or 0))
        monthly_chart_totals.append(total_chart_earnings)
        
    # Calculate chart total for each account
    bank_accounts = Accounts.objects.all()
    account_totals = {}
    account_labels = []
    for account in bank_accounts:
        totals = Payment.objects.filter(Account=account).aggregate(
            total_amount=Sum('amount'),
            total_discount_amount=Sum('discount_amount')
        )
        
        total_amount = totals['total_amount'] or 0
        total_discount_amount = totals['total_discount_amount'] or 0
        
        account_total = total_amount - total_discount_amount
        account_totals[account.id] = float(account_total)
        account_labels.append(account.Name)
    print("---account_totals----",account_totals)
    context['all_patient'] = all_patient
    context['total_day_earnings'] = total_day_earnings 
    context['total_monthly_earnings'] = total_monthly_earnings 
    context['total_yearly_earnings'] = total_yearly_earnings 
    # chart
    context['monthly_chart_totals'] = monthly_chart_totals
    context['labels'] = account_labels
    context['account_totals'] = json.dumps(account_totals)
    context['account_labels'] = json.dumps(account_labels)
    
    return render(request, 'index.html', context)


# user
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
            form=CustomUserForm(request.POST, request.FILES)   
            if form.is_valid():
                new_user=form.save()
                
                # changed_data = {}
                # for field in form.changed_data:
                #     if field.startswith('password'):
                #         continue
                #     new_value = form.cleaned_data.get(field)
                #     if new_value is not None:
                #         changed_data[field] = new_value
                # changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
                
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
                
                changed_data = {}
                for field in form.changed_data:
                    new_value = form.cleaned_data.get(field)
                    if new_value is not None:
                        changed_data[field] = new_value
                changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
                
                if next_url:
                    messages.success(request,profile_edit)
                    fnlog(request,edit_user,'Edited_Profile',f"Changes : {changes_str}",'')
                    return redirect(next_url)  # Redirect to the previous page
                else:
                    messages.success(request,user_edit)
                    fnlog(request,edit_user,'Edited_User',f"Changes : {changes_str}",'')
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


#activity logs  
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
     
    
# password change
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


# path
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
            
            changed_data = {}
            for field in form.changed_data:
                new_value = form.cleaned_data.get(field)
                if new_value is not None:
                    changed_data[field] = new_value
            changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
            
            fnlog(request,None,'Admin_and_Staff',"Edit Path",f"Changes : {changes_str}")
            messages.success(request,path_edit)
            return redirect(Profile)
        
        form.fields['parent'].queryset = Path.objects.filter(status='Active')
        context['form']=form
        context['edit']=1
            
        return render(request,'path/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
# role 
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
            
            changed_data = {}
            for field in form.changed_data:
                new_value = form.cleaned_data.get(field)
                if new_value is not None:
                    changed_data[field] = new_value
            changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
            
            fnlog(request,None,'Admin_and_Staff',"Edit Role",f"Changes : {changes_str}")
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
    
    
#site settings 
@login_required(login_url="login")
def site_settings(request):
    if request.user.is_superuser or PermisionsOf(request,'Site Settings').has_permission():
        context=get_menu(request)
        Site_data=Site_settings.objects.all()
        context['Site_data']=Site_data
        return render(request,'site_settings/site_settings.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")     
    
@login_required(login_url="login")
def add_site_settings(request):
    if request.user.is_superuser or PermisionsOf(request,'Add Site Settings').has_permission():
        context=get_menu(request)
        form=SiteSettingsForm()
        context['form']=form

        if request.method=="POST":
            form=SiteSettingsForm(request.POST, request.FILES)
            if form.is_valid():
                form.save()
                fnlog(request,None,'Admin_and_Staff',"Add Site Settings",'')
                messages.success(request,site_settings_add)
                return redirect(site_settings)
                
            else:
                form=RoleForm()
                context['form']=form
                return render(request,'site_settings/add_form.html',context)
                
        return render(request,'site_settings/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")
    

@login_required(login_url="login")
def edit_site_settings(request,site_settingsedit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit Site Settings').has_permission():
        context=get_menu(request)
        Site_data=Site_settings.objects.get(id=site_settingsedit_id)
        form=SiteSettingsForm(request.POST or None, request.FILES or None,instance=Site_data)
        context['form']=form

        if form.is_valid():
            form.save()
            
            changed_data = {}
            for field in form.changed_data:
                new_value = form.cleaned_data.get(field)
                if new_value is not None:
                    changed_data[field] = new_value
            changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
            
            fnlog(request,None,'Admin_and_Staff',"Edit Site Settings",f"Changes : {changes_str}")
            messages.success(request,site_settings_edit)
            return redirect(site_settings)
            
        return render(request,'site_settings/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")
    
    
# bank account section
@login_required(login_url="login")
def View_account(request):
    if request.user.is_superuser or PermisionsOf(request,'View Bank Account').has_permission():
        context=get_menu(request)
        bank_accounts=Accounts.objects.all().order_by("-id").order_by('Name')
        # if request.method=="GET":
        #     Name=request.GET.get('Name')
        #     status=request.GET.get('status')
        #     if Name:
        #         bank_accounts=bank_accounts.filter(Name__icontains=Name)
        #     if status:
        #         bank_accounts =bank_accounts.filter(status__iexact=status.capitalize())

        # paginator=Paginator(bank_accounts,20)
        # page_num=request.GET.get('page')
        # bank_accounts_page = paginator.get_page(page_num)
        account_totals = {}
        for account in bank_accounts:
            totals = Payment.objects.filter(Account=account).aggregate(
                total_amount=Sum('amount'),
                total_discount_amount=Sum('discount_amount')
            )
            
            total_amount = totals['total_amount'] or 0
            total_discount_amount = totals['total_discount_amount'] or 0
            
            account_total = total_amount - total_discount_amount
            
            account_totals[account.id] = account_total
            
        context['account_totals'] = account_totals
        context['bank_accounts'] = bank_accounts
        return render(request,'bank_account/form_data.html',context)
    else:
        messages.error(request,page_deny)
        return redirect("admin")

@login_required(login_url="login")
def Add_account(request):
    if request.user.is_superuser or PermisionsOf(request,'Add Bank Account').has_permission():
        context=get_menu(request)
        form=Accounts_Form()
        context['form']=form
        if request.method=="POST":
            form=Accounts_Form(request.POST)

            if form.is_valid():
                instance=form.save(commit=False)
                instance.Created_by = request.user
                instance.save()
                fnlog(request,None,'Admin_and_Staff',"Add Payment Account",'')
                messages.success(request,account_add)
                return redirect(View_account)
            else:
                print(form.errors)
                context['form']=form
                return render(request,'bank_account/add_form.html',context)
                
        return render(request,'bank_account/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")

@login_required(login_url="login")
def Edit_account(request,accountedit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit Bank Account').has_permission():
        context=get_menu(request)
        bank_account=Accounts.objects.get(id=accountedit_id)
        form=Accounts_Form(request.POST or None,instance=bank_account)
        context['form']=form
        context['edit']=1

        if form.is_valid():
            instance=form.save(commit=False)
            instance.Created_by = request.user
            instance.save()
            
            changed_data = {}
            for field in form.changed_data:
                new_value = form.cleaned_data.get(field)
                if new_value is not None:
                    changed_data[field] = new_value
            changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
            
            fnlog(request,None,'Admin_and_Staff',"Edit Payment Account",f"Changes : {changes_str}")
            messages.success(request,account_edit)
            return redirect(View_account)
            
        return render(request,'bank_account/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin") 
    
    
    
# patient and client 
    # patient
@login_required(login_url="login")
def View_patient(request):
    if request.user.is_superuser or PermisionsOf(request,'View Patient').has_permission():
        context=get_menu(request)
        patients=Patient_And_Client.objects.all().order_by("-User_id")
        # if request.method=="GET":
        #     Name=request.GET.get('Name')
        #     status=request.GET.get('status')
        #     if Name:
        #         bank_accounts=bank_accounts.filter(Name__icontains=Name)
        #     if status:
        #         bank_accounts =bank_accounts.filter(status__iexact=status.capitalize())

        # paginator=Paginator(bank_accounts,20)
        # page_num=request.GET.get('page')
        # bank_accounts_page = paginator.get_page(page_num)
        context['patients'] = patients
        return render(request,'patient/form_data.html',context)
    else:
        messages.error(request,page_deny)
        return redirect("admin")

def generate_user_id():
    prefix = "P-"
    last_patient = Patient_And_Client.objects.filter(User_id__startswith=prefix).order_by('User_id').last()
    if last_patient:
        last_id = int(last_patient.User_id.split('-')[-1])
        new_id = last_id + 1
    else:
        new_id = 1
    return f"{prefix}{new_id:02d}"


@login_required(login_url="login")
def Add_patient(request):
    if request.user.is_superuser or PermisionsOf(request,'Add Patient').has_permission():
        context=get_menu(request)
        form=patient_and_client_Form()
        context['form']=form
        if request.method=="POST":
            form=patient_and_client_Form(request.POST, request.FILES)

            if form.is_valid():
                instance=form.save(commit=False)
                instance.Created_by = request.user
                instance.User_id = generate_user_id()
                instance.save()
                fnlog(request,None,'Admin_and_Staff',"Add Patient",f"{instance.first_name} - {instance.User_id}")
                messages.success(request,patient_add)
                return redirect(View_patient)
            else:
                print(form.errors)
                context['form']=form
                return render(request,'patient/add_form.html',context)
                
        return render(request,'patient/add_form.html',context)
    
    else:
        messages.error(request,page_deny)
        return redirect("admin")

@login_required(login_url="login")
def Edit_patient(request,patientedit_id):

    if request.user.is_superuser or PermisionsOf(request,'Edit Patient').has_permission():
        next_url = request.GET.get('next_url', None)
        print('-----------',next_url)
        context=get_menu(request)
        patient = get_object_or_404(Patient_And_Client, id=patientedit_id)
        form=patient_and_client_Form(request.POST or None, request.FILES or None, instance=patient)
        context['form']=form
        context['edit']=1
        context['patient'] = patient

        if form.is_valid():
            instance=form.save(commit=False)
            instance.Created_by = request.user
            instance.User_id = patient.User_id
            instance.save()
            
            changed_data = {}
            for field in form.changed_data:
                new_value = form.cleaned_data.get(field)
                if new_value is not None:
                    changed_data[field] = new_value
            changes_str = ", ".join([f"{field}: {value}" for field, value in changed_data.items()])
            
            # return redirect(View_patient)
            if next_url:
                messages.success(request,patient_edit)
                fnlog(request,None,'Admin_and_Staff',f"Edit Patient : {instance.first_name} - {instance.User_id}",f"Changes : {changes_str}")
                return redirect(next_url)  # Redirect to the previous page
            else:
                messages.success(request,patient_edit)
                fnlog(request,None,'Admin_and_Staff',f"Edit Patient : {instance.first_name} - {instance.User_id}",f"Changes : {changes_str}")
                return redirect(View_patient)
            
        return render(request,'patient/add_form.html',context)

    else:
        messages.error(request,page_deny)
        return redirect("admin")

def generate_transaction_id():
    last_transaction = Transactions.objects.all().order_by('id').last()
    if not last_transaction or not last_transaction.Invoice_number.startswith('invd-'):
        return 'invd-01'
    try:
        new_number = int(last_transaction.Invoice_number.split('-')[1]) + 1
    except (IndexError, ValueError):
        return 'invd-01'
    
    # Check if the new number already exists
    new_invoice_number = f'invd-{new_number:02d}'
    while Transactions.objects.filter(Invoice_number=new_invoice_number).exists():
        new_number += 1
        new_invoice_number = f'invd-{new_number:02d}'
    
    return new_invoice_number


@login_required(login_url="login")
def Patient_list(request, patientview_id):
    if request.user.is_superuser or PermisionsOf(request, 'View Patient').has_permission():
        context = get_menu(request)
        view_patient = Patient_And_Client.objects.get(id=patientview_id)
        
        patient_transactions = Transactions.objects.filter(User=view_patient)
        
        totals = patient_transactions.aggregate(total_amount=Sum('Total_amount'),
                                                    total_discount=Sum('Discount'))
        total_amount = (totals['total_amount'] or 0) - (totals['total_discount'] or 0)
        total_paid_amount = patient_transactions.aggregate(Sum('Paid_amount'))['Paid_amount__sum'] or 0
        
        if total_amount > 0:
            progress_percentage = (total_paid_amount / total_amount) * 100
        else:
            progress_percentage = 0
            
        total_advance = patient_transactions.aggregate(Sum('Advance'))['Advance__sum'] or 0
        total_balance = patient_transactions.aggregate(Sum('Balance'))['Balance__sum'] or 0
        
        if total_balance > 0:
            progress_percentage_balance = (total_amount - total_balance) / total_amount * 100
        else:
            progress_percentage_balance = 0

        if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            transaction_id = request.POST.get('transaction_id', None)
            if transaction_id:
                transaction = get_object_or_404(Transactions, id=transaction_id)
                form = TransactionsForm(request.POST, instance=transaction)
            else:
                form = TransactionsForm(request.POST)
            
            if form.is_valid():
                if transaction_id:
                    form.save()
                    messages.success(request, "Transaction edited successfully.")
                    response = {
                        'status': 'success',
                        'message': 'Transaction edited successfully.'
                    }
                    fnlog(request, None, 'Admin_and_Staff', f"Transaction edited: {view_patient.first_name} - {view_patient.User_id}", "")
                else:
                    # Invoice_number = generate_transaction_id()
                    new_transaction = form.save(commit=False)
                    # new_transaction.Invoice_number = Invoice_number
                    new_transaction.Type = 0
                    new_transaction.Transaction_type = 0
                    new_transaction.Created_by = request.user
                    new_transaction.User = view_patient
                    new_transaction.save()
                    
                    response = {
                        'status': 'success',
                        'message': 'New transaction created successfully.'
                    }
                    messages.success(request, "New transaction created successfully.")
                    fnlog(request, None, 'Admin_and_Staff', f"New transaction created: {view_patient.first_name} - {view_patient.User_id}", "")
                return JsonResponse(response)
            else:
                errors = dict(form.errors.items())
                return JsonResponse({'status': 'error', 'errors': errors})
        
        context['view_patient'] = view_patient
        context['patient_transactions'] = patient_transactions
        context['total_amount'] = total_amount
        context['total_paid_amount'] = total_paid_amount
        context['progress_percentage'] = progress_percentage 
        context['total_advance'] = total_advance
        context['total_balance'] = total_balance
        context['progress_percentage_balance'] = progress_percentage_balance
        
        return render(request, 'patient/view_patient.html', context)
    else:
        messages.error(request, page_deny)
        return redirect("admin")
    
def transaction_detail(request, patientview_id, transaction_id):
    if transaction_id:
        transaction = get_object_or_404(Transactions, id=transaction_id)
        data = {
            'Date': transaction.Date.strftime('%Y-%m-%d'),  # Format date for input[type="date"]
            'Remark': transaction.Remark,
        }
        return JsonResponse(data)
    else:
        return JsonResponse({'Date': '', 'Remark': ''})
    
def calculate_total_amount(transaction_id):
    transaction = get_object_or_404(Transactions, id=transaction_id)
    total = transaction.Payments.aggregate(total_amount=Sum('amount'))['total_amount']
    return total if total is not None else Decimal('0.00')
    
#  patient payment 
@login_required(login_url="login")
def make_payment(request, patientview_id, transaction_id):

    if request.user.is_superuser or PermisionsOf(request, 'View Payment').has_permission():
        context = get_menu(request)
        transaction = get_object_or_404(Transactions, id=transaction_id)
        payments = Payment.objects.filter(transactions=transaction)
        accounts = Accounts.objects.all()
                
        if request.method == 'POST':
            formset = PaymentFormSet(request.POST, queryset=payments)
            advance = decimal.Decimal(request.POST.get('Advance', '0'))
            discount = decimal.Decimal(request.POST.get('Discount', '0'))
            
            new_total_amount = Decimal('0.00')
            new_discount = Decimal('0.00')
            new_advance = Decimal('0.00')
            
            if formset.is_valid():
                new_discount = Decimal(request.POST.get('Discount', '0'))
                new_advance = Decimal(request.POST.get('Advance', '0')) 
                mark_as_paid = Decimal(request.POST.get('mark_as_paid', '0'))
                account_id = request.POST.get('Account')
                account = get_object_or_404(Accounts, pk=account_id)
                
                for form in formset:
                    if form.cleaned_data.get('amount'):
                        new_total_amount += form.cleaned_data['amount']
                
                saved_payments = []        
                for form in formset:
                    if form.cleaned_data.get('amount'):
                        # Save each payment entry to the database
                        payment = form.save(commit=False)
                        payment.Created_by = request.user
                        payment.Account = account
                        if new_discount > 0:
                            payment.discount_amount = (new_discount / new_total_amount) * payment.amount
                        payment.save()
                        saved_payments.append(payment)
                 
                 
                # Associate payments with the transaction
                transaction.Payments.add(*saved_payments)

                total_amount = calculate_total_amount(transaction.id) 
                
                if not transaction.Invoice_number:
                    transaction.Invoice_number = generate_transaction_id()
                
                transaction.Total_amount = total_amount
                transaction.Advance += new_advance
                transaction.Discount += new_discount
                
                if 'paid_checkbox' in request.POST:
                    transaction.Balance
                    transaction.Paid_amount += new_total_amount - new_discount 
                else:
                    if new_advance:
                        transaction.Paid_amount += new_advance
                    else:
                        transaction.Paid_amount += mark_as_paid
                    if new_advance:
                        # Calculate balance based on total amount, discount, and advance
                        new_balance = new_total_amount - new_discount - new_advance
                    else:
                        # Calculate balance based on total amount, discount, and advance
                        new_balance = new_total_amount - new_discount - mark_as_paid
                    # If balance is negative, set it to 0 to prevent negative balances
                    transaction.Balance += new_balance 
                    
                transaction.save()
                
                
                messages.success(request, 'Payment made successfully.')
                if mark_as_paid:
                    fnlog(request, None, 'Admin_and_Staff', f"Payment Created: {transaction.Invoice_number} - Total Amount: {mark_as_paid} - Payment Type: {account}", "")
                else:
                    fnlog(request, None, 'Admin_and_Staff', f"Payment Created: {transaction.Invoice_number} - Total Amount: {new_total_amount} - Discount: {new_discount} - Payment Type: {account}", "")
                return HttpResponseRedirect(reverse('make_payment', args=[patientview_id, transaction_id]))
            else:
                error_message = "Error making payment. Please correct the following errors:"
                for form_errors in formset.errors:
                    for error in form_errors.values():
                        print(error)
                        error_message += f"\n- {error}"
                messages.error(request, error_message)
                return HttpResponseRedirect(reverse('make_payment', args=[patientview_id, transaction_id]))
        else:
            formset = PaymentFormSet(queryset=Payment.objects.none())
        
        context = {
            'formset': formset,
            'transaction': transaction,
            'payments': payments,
            'accounts': accounts,
            'patientview_id': patientview_id
        }

        return render(request,'patient/patient_payment.html',context)

    else:
        messages.error(request, page_deny)
        return redirect("admin")