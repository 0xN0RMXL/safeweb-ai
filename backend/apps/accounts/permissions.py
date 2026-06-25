from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Allow access only to admin users."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and (request.user.role == 'admin' or request.user.is_superuser)
        )


class IsOwner(BasePermission):
    """Allow access only to the owner of the resource."""

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return obj == request.user


class IsOrganizationAdmin(BasePermission):
    """Allow access only if the user is an owner or admin of the active organization."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        org = getattr(request, 'organization', None)
        if not org:
            return False
        from .models import OrganizationMembership
        membership = OrganizationMembership.objects.filter(user=request.user, organization=org).first()
        return membership and membership.role in ['owner', 'admin']


class CanStartScan(BasePermission):
    """Allow access only if the user is not a viewer in the active organization."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        org = getattr(request, 'organization', None)
        if not org:
            return False
        from .models import OrganizationMembership
        membership = OrganizationMembership.objects.filter(user=request.user, organization=org).first()
        return membership and membership.role != 'viewer'
