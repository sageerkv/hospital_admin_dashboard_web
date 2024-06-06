import re
from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm,SetPasswordForm
from django.core.validators import EmailValidator
from django.contrib.auth.models import Group, Permission
from .models import *
from .allmessages import *
from django.forms import modelformset_factory


class DateInput(forms.DateInput):
    input_type = 'date'

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

class CustomUserForm(UserCreationForm):
    class Meta:
        model=CustomUser
        fields=('first_name', 'last_name', 'profile_img', 'password1', 'password2','email','role','Type','Phone_number', 'status')
        
    def __init__(self, *args, **kwargs):
        super(CustomUserForm, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            self.fields['Phone_number'].required = False
            self.fields['profile_img'].required = False
    
    def save(self,commit=True):
        user=super(CustomUserForm,self).save(commit=False)
        user.role=self.cleaned_data['role']
        user.email=self.cleaned_data['email']
        if commit:
            user.save()
            return user

    def clean_email(self):
        email = self.cleaned_data.get('email')

        if email and not re.match(EMAIL_REGEX, str(email)):
            raise forms.ValidationError(emailformat)

        return email

class EditUserForm(UserChangeForm):
    class Meta:
        model=CustomUser
        fields=('first_name', 'last_name','profile_img', 'email','role','Type','Phone_number', 'status')
    
    def __init__(self, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            self.fields['Phone_number'].required = False
            self.fields['profile_img'].required = False

    def save(self,commit=True):
        user=super(EditUserForm,self).save(commit=False)
        user.role=self.cleaned_data['role']
        user.email=self.cleaned_data['email']
        if commit:
            user.save()
            return user
        
        
        
        
class ChangeUserPasswordForm(SetPasswordForm):
    class Meta:
        model=CustomUser
        fields=('new_password1','new_password2')

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangeUserPasswordForm, self).__init__(user,*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError("Both Passwords doesnt match")
        return password2

    def save(self,commit=True):
        user=super(ChangeUserPasswordForm,self).save(commit=False)
        user.set_password(self.cleaned_data["new_password1"])
        if commit:
            user.save()
            return user
        
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and not re.match(EMAIL_REGEX, str(email)):
            raise forms.ValidationError("Invalid email format")
        return email
    
    
    
class PathForm(forms.ModelForm):
    class Meta:
        model=Path
        fields="__all__"

    def __init__(self, *args, **kwargs):
        super(PathForm, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            
            
class RoleForm(forms.ModelForm):
    class Meta:
        model=Role
        fields="__all__"

    def __init__(self, *args, **kwargs):
        super(RoleForm, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            
            
class SiteSettingsForm(forms.ModelForm):
    class Meta:
        model=Site_settings
        fields="__all__"

    def __init__(self, *args, **kwargs):
        super(SiteSettingsForm, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            
            
            
class Accounts_Form(forms.ModelForm):
    class Meta:
        model=Accounts
        fields="__all__"
        exclude = ['Created_by']

    def __init__(self, *args, **kwargs):
        super(Accounts_Form, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            self.fields[name].required = True
            
            
            
class patient_and_client_Form(forms.ModelForm):
    class Meta:
        model=Patient_And_Client
        fields="__all__"
        exclude = ['Created_by','User_id']
        widgets = {
            'remark': forms.Textarea(attrs={'rows': 5, 'cols': 30, 'style': 'height: auto;'}),
        }

    def __init__(self, *args, **kwargs):
        super(patient_and_client_Form, self).__init__(*args, **kwargs)
        for name in self.fields.keys():
            self.fields[name].widget.attrs.update({'class':'form-control'})
            self.fields[name].required = True
        
        self.fields['last_name'].required = False
        self.fields['remark'].required = False
        self.fields['profile_img'].required = False
        
class TransactionsForm(forms.ModelForm):
    class Meta:
        model = Transactions
        fields = ['Date', 'Remark']
        widgets = {
            'Date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'Remark': forms.Textarea(attrs={'rows': 5, 'cols': 30, 'style': 'height: auto;', 'class': 'form-control'}),
        }

class PaymentForm(forms.ModelForm):
    class Meta:
        model = Payment
        fields = ['amount', 'Remark']
        widgets = {
            'amount': forms.TextInput(attrs={'class': 'form-control'}),
            'Remark': forms.Textarea(attrs={'rows': 1, 'cols': 30, 'style': 'height: auto;', 'class': 'form-control'}),
        }
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['amount'].required = True
        
PaymentFormSet = modelformset_factory(Payment, form=PaymentForm, extra=1)