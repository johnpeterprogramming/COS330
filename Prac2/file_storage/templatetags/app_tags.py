from django import template
from django.contrib.auth.models import Group

register = template.Library()


@register.filter(name='has_group')
def has_group(user, group_names: str) -> bool:
    """
    Usage: {% if user|has_group:["Admin,Manager,User"] %}
    """
    if not user.is_authenticated:
        return False
    names = [g.strip() for g in group_names.split(',') if g.strip()]
    return user.groups.filter(name__in=names).exists()
