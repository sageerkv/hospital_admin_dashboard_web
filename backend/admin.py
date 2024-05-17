from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _


admin.site.register(CustomUser)
admin.site.register(UserLog)
admin.site.register(Role)
admin.site.register(Path)
admin.site.register(Site_settings)
