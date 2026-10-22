# SPDX-FileCopyrightText: (C) ColdFront Authors
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from django.utils.safestring import mark_safe
from django import forms


class PublicationAddForm(forms.Form):
    title = forms.CharField(max_length=1024, required=True)
    author = forms.CharField(max_length=1024, required=True)
    year = forms.IntegerField(min_value=1500, max_value=2090, required=True)
    journal = forms.CharField(max_length=1024, required=True)
    source = forms.CharField(widget=forms.HiddenInput())  # initialized by view
    used_rc = forms.BooleanField(
        initial=False, label="Used RC resources", help_text="Did this publication use RC resources?"
    )
    cited_rc = forms.BooleanField(
        initial=False,
        label="Cited Research Computing",
        help_text=mark_safe(
            "Did this publication cite Research Computing? <a href='https://mirrors.rit.edu/publications/#citation--acknowledgment'>Citation Instructions</a>"
        ),
    )


class PublicationSearchForm(forms.Form):
    search_id = forms.CharField(label="Search ID", widget=forms.Textarea, required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["search_id"].help_text = "<br/>Enter ID such as DOI or Bibliographic Code to search."


class PublicationResultForm(forms.Form):
    title = forms.CharField(max_length=1024, disabled=True)
    author = forms.CharField(disabled=True)
    year = forms.CharField(max_length=4, disabled=True)
    journal = forms.CharField(max_length=1024, disabled=True)
    unique_id = forms.CharField(max_length=255, disabled=True)
    source_pk = forms.IntegerField(widget=forms.HiddenInput(), disabled=True)
    selected = forms.BooleanField(initial=True, required=False)
    used_rc = forms.BooleanField(
        initial=False,
        label="Used RC resources",
        help_text="Did this publication use RC resources?",
        required=False,
    )
    cited_rc = forms.BooleanField(
        initial=False,
        label="Cited Research Computing",
        help_text="Did this publication cite Research Computing?",
        required=False,
    )


class PublicationDeleteForm(forms.Form):
    title = forms.CharField(max_length=255, disabled=True)
    year = forms.CharField(max_length=30, disabled=True)
    selected = forms.BooleanField(initial=False, required=False)


class PublicationExportForm(forms.Form):
    title = forms.CharField(max_length=255, disabled=True)
    year = forms.CharField(max_length=30, disabled=True)
    unique_id = forms.CharField(max_length=255, disabled=True)
    selected = forms.BooleanField(initial=False, required=False)
