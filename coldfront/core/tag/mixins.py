from django import forms
from django.contrib.contenttypes.models import ContentType
from django.forms import widgets

from coldfront.core.tag.models import Tag


class TagSelectWidget(widgets.SelectMultiple):
    class Media:
        js = ["tag/tag_select.js"]


class TagsMixin(forms.Form):
    tags = forms.ModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False,
        label="Tags",
        widget=TagSelectWidget,
    )

    def __init__(self, request, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Limit tags to those applicable to the object type
        object_type = ContentType.objects.get_for_model(self._meta.model)
        if object_type:
            self.fields["tags"].queryset = Tag.get_allowed_tags(object_type, request.user)
