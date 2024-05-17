from django import template
from datetime import datetime
from core.settings import *
from backend.models import Site_settings

register = template.Library()

@register.filter(name='has_permission')
def has_permission(user, permission_name):
    if user.is_superuser:
        return True
    else:
        return user.role.permissions.filter(path_name=permission_name).exists()
    
    
@register.simple_tag
def company_name(default_value="Company name"):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        name = site_settings_instance.company_name
        print(name, 'name..........')
        if name is not None:
            print(name, 'currency_symbol..........')
            return name
    print(default_value, 'default_value..........')
    return default_value
    

@register.simple_tag
def company_phone(default_value="910000000000"):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        contact = site_settings_instance.contact
        print(contact, 'phone..........')
        if contact is not None:
            print(contact, 'contact..........')
            return contact
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_mail(default_value="sample@gmail.com"):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        mail = site_settings_instance.mail
        print(mail, 'mail..........')
        if mail is not None:
            print(mail, 'mail..........')
            return mail
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_facebook(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        facebook_link = site_settings_instance.facebook_link
        print(facebook_link, 'facebook_link..........')
        if facebook_link is not None:
            print(facebook_link, 'facebook_link..........')
            return facebook_link
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_twitter(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        Twitter_link = site_settings_instance.Twitter_link
        print(Twitter_link, 'Twitter_link..........')
        if Twitter_link is not None:
            print(Twitter_link, 'Twitter_link..........')
            return Twitter_link
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_youtube(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        Youtube_link = site_settings_instance.Youtube_link
        print(Youtube_link, 'Youtube_link..........')
        if Youtube_link is not None:
            print(Youtube_link, 'Youtube_link..........')
            return Youtube_link
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_instagram(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        instagram_link = site_settings_instance.instagram_link
        print(instagram_link, 'instagram_link..........')
        if instagram_link is not None:
            print(instagram_link, 'instagram_link..........')
            return instagram_link
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_copyright(default_value="company copy right"):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        copyright = site_settings_instance.copyright
        print(copyright, 'copyright..........')
        if copyright is not None:
            print(copyright, 'copyright..........')
            return copyright
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def adress_1(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        address_line_1 = site_settings_instance.address_line_1
        print(address_line_1, 'address_line_1..........')
        if address_line_1 is not None:
            print(address_line_1, 'address_line_1..........')
            return address_line_1
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def adress_2(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        address_line_2 = site_settings_instance.address_line_2
        print(address_line_2, 'address_line_2..........')
        if address_line_2 is not None:
            print(address_line_2, 'address_line_2..........')
            return address_line_2
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def adress_3(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        address_line_3 = site_settings_instance.address_line_3
        print(address_line_3, 'address_line_3..........')
        if address_line_3 is not None:
            print(address_line_3, 'address_line_3..........')
            return address_line_3
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def adress_4(default_value=""):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        address_line_4 = site_settings_instance.address_line_4
        print(address_line_4, 'address_line_4..........')
        if address_line_4 is not None:
            print(address_line_4, 'address_line_4..........')
            return address_line_4
    print(default_value, 'default_value..........')
    return default_value

@register.simple_tag
def company_whatsapp():
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        whatsapp_number = site_settings_instance.whatsapp_number
        print(whatsapp_number, 'instagram_link..........')
        return whatsapp_number
    else:
        return ""

@register.simple_tag
def company_whatsapp_contact_number():
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        whatsapp_contact_number = site_settings_instance.whatsapp_contact_number
        print(whatsapp_contact_number, 'whatsapp_contact_number..........')
        return whatsapp_contact_number
    else:
        return ""

path=BASE_PATH
logo_name=IMAGE_LOGO_NAME
fav_name=FAV_ICON_NAME
IMAGE_PATH=f'{path}/{logo_name}'
FAV_PATH=f'{path}/{fav_name}'

@register.simple_tag
def logo_path(default_value=IMAGE_PATH):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance and site_settings_instance.logo:
        logo = site_settings_instance.logo.url
        print(logo, 'logo..........')
        if logo is not None:
            print(logo, 'logo..........')
            return logo
    print(default_value, 'logo_value..........')
    return default_value

    
@register.simple_tag
def fav_path(default_value=FAV_PATH):
    site_settings_instance = Site_settings.objects.first()  
    if site_settings_instance and site_settings_instance.favicon:
        favicon = site_settings_instance.favicon.url
        print(favicon, 'favicon..........')
        if favicon is not None:
            print(favicon, 'favicon..........')
            return favicon
    print(default_value, 'favicon_value..........')
    return default_value

# url=WEB_URL
@register.simple_tag
def web_url():
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        web_url = site_settings_instance.web_url
        print(web_url, 'web_url..........')
        return web_url
    else:
        return ""
    
    
# color
@register.simple_tag
def company_constant_color(default_value="#4e73df"):
    site_settings_instance = Site_settings.objects.first()
    if site_settings_instance:
        constant_color = site_settings_instance.constant_color
        print(constant_color, 'constant_color..........')
        if constant_color is not None:
            print(constant_color, 'constant_color..........')
            return constant_color
     # If currency_symbol is None or site_settings_instance is None
    print(default_value, 'default_value..........')
    return default_value