from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager


class Path(models.Model):
    path_name = models.CharField(max_length=100, unique=True)
    status = models.CharField(max_length=20, default="Active", choices=(
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ))
    parent = models.ForeignKey('Path', on_delete=models.CASCADE, null=True, blank=True)
    Created_at = models.DateTimeField(auto_now_add=True)
    Updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'Path'

    def __str__(self):
        return self.path_name


class Role(models.Model):
    role = models.CharField(max_length=100, unique=True)
    status = models.CharField(max_length=20, default='Active', choices=(
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
    ))
    permissions = models.ManyToManyField(Path, null=True, blank=True, related_name='roles')
    Created_at = models.DateTimeField(auto_now_add=True)
    Updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'Role'
        ordering = ['role']

    def __str__(self):
        return self.role


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The email must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=30, unique=True)
    Phone_number=models.BigIntegerField(null=True, blank=True)  
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True)
    is_staff=models.BooleanField(default=True,null=True,blank=True)
    status = models.CharField(max_length=20, default="Active", choices=(
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ), null=True, blank=True)
    loginAttempts = models.IntegerField(default=0)
    Created_at = models.DateTimeField(auto_now=True)
    Updated_at = models.DateTimeField(auto_now=True)
    Type = models.CharField(max_length=20, default="Staff", choices=(
        ('Admin', 'Admin'),
        ('Staff', 'Staff'),
        ('Doctor', 'Doctor')
    ), null=True, blank=True)
    profile_img = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name']


    def __str__(self):
        return self.email
    
    
class UserLog(models.Model):
    created_at=models.DateTimeField(auto_now=True)
    log_type=models.CharField(max_length=100,choices=(
        ('Created_User','Created_User'),
        ('Edited_User','Edited_User'),
        ('Edited_Profile','Edited_Profile'),
        ('Logged_in','Logged_in'),
        ('Password_changed','Password_changed'),
        ('Activated','Activated'),
        ('Deactivated','Deactivated'),
        ('Admin_and_Staff','Admin_and_Staff'),
    ))
    created_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_user_logs')
    effected_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='effected_user_logs', blank=True, null=True)
    reason=models.CharField(max_length=100,null=True,blank=True)
    remarks=models.TextField(max_length=500,null=True,blank=True)

    class Meta:
        db_table = 'UserLog'
        ordering = ['-created_at']
        
        
class Site_settings(models.Model):
    company_name = models.CharField(max_length = 500,blank=True,null=True)
    contact=models.CharField(max_length=20,blank=True,null=True)
    mail = models.EmailField(unique=True,blank=True,null=True)
    copyright = models.CharField(max_length = 500,blank=True,null=True)
    facebook_link = models.CharField(max_length = 500,blank=True,null=True)
    instagram_link = models.CharField(max_length = 500,blank=True,null=True)
    Youtube_link = models.CharField(max_length = 500,blank=True,null=True)
    Twitter_link = models.CharField(max_length = 500,blank=True,null=True)
    address_line_1 = models.CharField(max_length = 500,blank=True,null=True)
    address_line_2 = models.CharField(max_length = 500,blank=True,null=True)
    address_line_3 = models.CharField(max_length = 500,blank=True,null=True)
    address_line_4 = models.CharField(max_length = 500,blank=True,null=True)
    whatsapp_number = models.CharField(max_length = 500,blank=True,null=True)
    whatsapp_contact_number = models.CharField(max_length = 500,blank=True,null=True)
    logo = models.ImageField(upload_to='logo/', null=True, blank=True)
    favicon = models.ImageField(upload_to='favicon/', null=True, blank=True)
    web_url = models.CharField(max_length = 500,blank=True,null=True)
    # color
    constant_color = models.CharField(max_length = 500,blank=True,null=True)

    class Meta:
        db_table = 'Site Settings'
        ordering = ['-company_name']
        
        
class Accounts(models.Model):
    Name = models.CharField(max_length=255,null=True, blank=True, unique=True)
    Created_at = models.DateTimeField(auto_now_add=True)
    Updated_at = models.DateTimeField(auto_now=True)
    Created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_accounts', null=True, blank=True)
    status = models.CharField(max_length=20, default="Active", choices=(
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ), null=True, blank=True)
    class Meta:
        db_table = 'Account'
        ordering = ['Name']

    def __str__(self):
        return f"{self.Name}"