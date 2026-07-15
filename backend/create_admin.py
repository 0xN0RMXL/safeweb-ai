import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.base')

import django
django.setup()

from apps.accounts.models import User, Organization, OrganizationMembership

admin_email = os.getenv('ADMIN_EMAIL', 'admin@safeweb.ai')
admin_username = os.getenv('ADMIN_USERNAME', 'admin')
admin_password = os.getenv('ADMIN_PASSWORD', 'SafeWeb@2026!')
admin_name = os.getenv('ADMIN_NAME', 'System Admin')

user = User.objects.filter(email=admin_email).first() or User.objects.filter(username=admin_username).first()

if not user:
    user = User.objects.create_superuser(
        username=admin_username,
        email=admin_email,
        password=admin_password,
        name=admin_name
    )
    print(f'Created superuser account: {user.email}')
else:
    user.is_superuser = True
    user.is_staff = True
    user.is_active = True
    user.role = 'admin'
    if not user.name:
        user.name = admin_name
    if not user.check_password(admin_password) or os.getenv('FORCE_ADMIN_PASSWORD_RESET', 'false').lower() == 'true':
        user.set_password(admin_password)
    user.save()
    print(f'Superuser account verified and password synced: {user.email}')

org, _ = Organization.objects.get_or_create(
    name='SafeWeb AI HQ',
    defaults={
        'plan_tier': 'enterprise',
        'owner': user
    }
)
OrganizationMembership.objects.get_or_create(
    user=user,
    organization=org,
    defaults={'role': 'owner'}
)
print(f'Organization verified for admin: {org.name}')
