import re
from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm,SetPasswordForm
from django.core.validators import EmailValidator
from django.contrib.auth.models import Group, Permission
from .models import *
from .allmessages import *


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