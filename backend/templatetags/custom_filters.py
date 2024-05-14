from django import template
from datetime import datetime
from core.settings import *

register = template.Library()

@register.filter(name='has_permission')
def has_permission(user, permission_name):
    if user.is_superuser:
        return True
    else:
        return user.role.permissions.filter(path_name=permission_name).exists()