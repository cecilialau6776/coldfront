import django.dispatch

allocation_new = django.dispatch.Signal()
    #providing_args=["allocation_pk"]
allocation_activate = django.dispatch.Signal()
    #providing_args=["allocation_pk"]
allocation_disable = django.dispatch.Signal()
    #providing_args=["allocation_pk"]

allocation_activate_user = django.dispatch.Signal()
    #providing_args=["allocation_user_pk"]
allocation_remove_user = django.dispatch.Signal()
    #providing_args=["allocation_user_pk"]

allocation_change_approved = django.dispatch.Signal()
    #providing_args=["allocation_pk", "allocation_change_pk"]

allocation_attribute_changed = django.dispatch.Signal()
    #providing_args=["attribute_pk", "allocation_pk"]
