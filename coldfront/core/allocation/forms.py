# SPDX-FileCopyrightText: (C) ColdFront Authors
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from enum import Enum

from django import forms
from django.contrib.auth import get_user_model
from django.db.models.functions import Lower
from django.forms import BaseModelFormSet, ValidationError
from django.shortcuts import get_object_or_404

from coldfront.config.core import ALLOCATION_EULA_ENABLE
from coldfront.core.allocation.models import (
    Allocation,
    AllocationAccount,
    AllocationAttribute,
    AllocationAttributeType,
    AllocationStatusChoice,
    AllocationUser,
    AllocationUserStatusChoice,
)
from coldfront.core.allocation.utils import get_user_resources
from coldfront.core.project.models import Project
from coldfront.core.resource.models import Resource, ResourceType
from coldfront.core.utils.common import import_from_settings

ALLOCATION_ACCOUNT_ENABLED = import_from_settings("ALLOCATION_ACCOUNT_ENABLED", False)
ALLOCATION_CHANGE_REQUEST_EXTENSION_DAYS = import_from_settings("ALLOCATION_CHANGE_REQUEST_EXTENSION_DAYS", [])
ALLOCATION_ACCOUNT_MAPPING = import_from_settings("ALLOCATION_ACCOUNT_MAPPING", {})
ALLOCATION_ENABLE_CHANGE_REQUESTS_BY_DEFAULT = import_from_settings(
    "ALLOCATION_ENABLE_CHANGE_REQUESTS_BY_DEFAULT", True
)

INVOICE_ENABLED = import_from_settings("INVOICE_ENABLED", False)
if INVOICE_ENABLED:
    INVOICE_DEFAULT_STATUS = import_from_settings("INVOICE_DEFAULT_STATUS", "Pending Payment")


class AllocationForm(forms.ModelForm):
    class Meta:
        model = Allocation
        fields = [
            "resource",
            "justification",
            "quantity",
            "users",
            "project",
            "is_changeable",
        ]
        help_texts = {
            "justification": "<br/>Justification for requesting this allocation.",
            "users": "<br/>Select users in your project to add to this allocation.",
        }
        widgets = {
            "status": forms.HiddenInput(),
            "project": forms.HiddenInput(),
            "is_changeable": forms.HiddenInput(),
        }

    resource = forms.ModelChoiceField(queryset=None, empty_label=None)
    users = forms.MultipleChoiceField(widget=forms.CheckboxSelectMultiple, required=False)
    allocation_account = forms.ChoiceField(required=False)

    def __init__(self, request_user, project_pk, *args, **kwargs):
        super().__init__(*args, **kwargs)
        project_obj = get_object_or_404(Project, pk=project_pk)

        # Set initial values
        self.fields["quantity"].initial = 1
        self.fields["is_changeable"].initial = ALLOCATION_ENABLE_CHANGE_REQUESTS_BY_DEFAULT
        self.fields["project"].initial = project_obj

        self.fields["resource"].queryset = get_user_resources(request_user).order_by(Lower("name"))

        # Set user choices
        user_query_set = (
            project_obj.projectuser_set.select_related("user")
            .filter(status__name__in=["Active"])
            .order_by("user__username")
            .exclude(user=project_obj.pi)
        )
        if user_query_set:
            self.fields["users"].choices = (
                (user.user.username, "%s %s (%s)" % (user.user.first_name, user.user.last_name, user.user.username))
                for user in user_query_set
            )
        else:
            self.fields["users"].widget = forms.HiddenInput()

        # Set allocation_account choices
        if ALLOCATION_ACCOUNT_ENABLED:
            allocation_accounts = AllocationAccount.objects.filter(user=request_user)
            if allocation_accounts:
                self.fields["allocation_account"].choices = (
                    ((account.name, account.name)) for account in allocation_accounts
                )
        else:
            self.fields["allocation_account"].widget = forms.HiddenInput()

    def clean(self):
        form_data = super().clean()
        project_obj = form_data.get("project")
        resource_obj = form_data.get("resource")
        allocation_account = form_data.get("allocation_account", None)

        # Ensure user has account name if ALLOCATION_ACCOUNT_ENABLED
        if (
            ALLOCATION_ACCOUNT_ENABLED
            and resource_obj.name in ALLOCATION_ACCOUNT_MAPPING
            and AllocationAttributeType.objects.filter(name=ALLOCATION_ACCOUNT_MAPPING[resource_obj.name]).exists()
            and not allocation_account
        ):
            raise ValidationError(
                'You need to create an account name. Create it by clicking the link under the "Allocation account" field.',
                code="user_has_no_account_name",
            )

        # Ensure this allocaiton wouldn't exceed the limit
        allocation_limit = resource_obj.get_attribute("allocation_limit", typed=True)
        if allocation_limit:
            allocation_count = project_obj.allocation_set.filter(
                resources=resource_obj,
                status__name__in=["Active", "New", "Renewal Requested", "Paid", "Payment Pending", "Payment Requested"],
            ).count()
            if allocation_count >= allocation_limit:
                raise ValidationError(
                    "Your project is at the allocation limit allowed for this resource.",
                    code="reached_allocation_limit",
                )

        # Set allocation status
        if INVOICE_ENABLED and resource_obj.requires_payment:
            allocation_status_name = INVOICE_DEFAULT_STATUS
        else:
            allocation_status_name = "New"
        form_data["status"] = AllocationStatusChoice.objects.get(name=allocation_status_name)
        self.instance.status = form_data["status"]

        return form_data


class AllocationUpdateForm(forms.ModelForm):
    class Meta:
        model = Allocation
        fields = [
            "status",
            "start_date",
            "end_date",
            "description",
            "is_locked",
            "is_changeable",
        ]

    status = forms.ModelChoiceField(
        queryset=AllocationStatusChoice.objects.all().order_by(Lower("name")), empty_label=None
    )
    start_date = forms.DateField(widget=forms.DateInput(attrs={"class": "datepicker"}), required=False)
    end_date = forms.DateField(widget=forms.DateInput(attrs={"class": "datepicker"}), required=False)

    def __init__(self, request_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not request_user.is_superuser:
            self.fields["is_locked"].disabled = True
            self.fields["is_changeable"].disabled = True

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get("start_date")
        end_date = cleaned_data.get("end_date")

        if start_date and end_date and end_date < start_date:
            raise forms.ValidationError("End date cannot be less than start date")


class AllocationInvoiceUpdateForm(forms.Form):
    status = forms.ModelChoiceField(
        queryset=AllocationStatusChoice.objects.filter(
            name__in=["Payment Pending", "Payment Requested", "Payment Declined", "Paid"]
        ).order_by(Lower("name")),
        empty_label=None,
    )


class AllocationUserForm(forms.ModelForm):
    class Meta:
        model = AllocationUser
        fields = ["id", "allocation", "user", "status"]
        widgets = {"id": forms.HiddenInput()}

    allocation = forms.ModelChoiceField(
        empty_label=None, queryset=Allocation.objects.none(), widget=forms.HiddenInput()
    )
    user = forms.ModelChoiceField(
        empty_label=None, queryset=get_user_model().objects.none(), widget=forms.HiddenInput()
    )
    status = forms.ModelChoiceField(
        empty_label=None, queryset=AllocationUserStatusChoice.objects.none(), widget=forms.HiddenInput()
    )
    selected = forms.BooleanField(initial=False, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        initial = kwargs.get("initial")
        instance = kwargs.get("instance")
        if instance:
            user = instance.user
            allocation = instance.allocation
            status = instance.status
        if initial:
            user = initial.get("user") or user
            allocation = initial.get("allocation") or allocation
            status = initial.get("status") or status
        else:
            return

        if user:
            self.fields["user"].queryset = get_user_model().objects.filter(pk=user.pk)
        if allocation:
            self.fields["allocation"].queryset = Allocation.objects.filter(pk=allocation.pk)
        if status:
            self.fields["status"].queryset = AllocationUserStatusChoice.objects.filter(pk=status.pk)

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.cleaned_data["selected"] and commit:
            instance.save()
        return instance


class BaseAllocationUserFormSet(BaseModelFormSet):
    template_name = "allocation/forms/formsets/allocation_user_formset.html"

    class Action(Enum):
        ADD = 1
        REMOVE = 2

    def __init__(self, action: Action, *args, **kwargs):
        self.action = action
        super().__init__(*args, **kwargs)

    def clean(self):
        """Checks that no two articles have the same title."""
        if any(self.errors):
            raise Exception(self.errors)
            return
        expected_allocation_user_status = self.form_kwargs["initial"]["status"]

        for form in self.forms:
            status = form.cleaned_data.get("status")
            if not form.cleaned_data.get("selected"):
                continue
            if status != expected_allocation_user_status:
                raise Exception(form.cleaned_data)
                raise ValidationError(
                    f"Submitted form should have {expected_allocation_user_status} AllocationUserStatus, instead got {status}"
                )
            user = form.cleaned_data.get("user")
            allocation = form.cleaned_data.get("allocation")

            if self.action == self.Action.ADD:
                user_is_pending_eula = ALLOCATION_EULA_ENABLE and not user.userprofile.is_pi and allocation.get_eula()
                if user_is_pending_eula:
                    allocation_user_status = AllocationUserStatusChoice.objects.get(name="PendingEULA")
                    form.cleaned_data["status"] = allocation_user_status
                    form.instance.status = form.cleaned_data["status"]
            elif self.action == self.Action.REMOVE:
                if allocation.project.pi == user:
                    raise ValidationError("Cannot remove the project PI from an allocation.")


class AllocationAttributeDeleteForm(forms.Form):
    pk = forms.IntegerField(required=False, disabled=True)
    name = forms.CharField(max_length=150, required=False, disabled=True)
    value = forms.CharField(max_length=150, required=False, disabled=True)
    selected = forms.BooleanField(initial=False, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pk"].widget = forms.HiddenInput()


class AllocationSearchForm(forms.Form):
    project = forms.CharField(label="Project Title", max_length=100, required=False)
    username = forms.CharField(label="Username", max_length=100, required=False)
    resource_type = forms.ModelChoiceField(
        label="Resource Type", queryset=ResourceType.objects.all().order_by(Lower("name")), required=False
    )
    resource_name = forms.ModelMultipleChoiceField(
        label="Resource Name",
        queryset=Resource.objects.filter(is_allocatable=True).order_by(Lower("name")),
        required=False,
    )
    allocation_attribute_name = forms.ModelChoiceField(
        label="Allocation Attribute Name",
        queryset=AllocationAttributeType.objects.all().order_by(Lower("name")),
        required=False,
    )
    allocation_attribute_value = forms.CharField(label="Allocation Attribute Value", max_length=100, required=False)
    end_date = forms.DateField(label="End Date", widget=forms.DateInput(attrs={"class": "datepicker"}), required=False)
    active_from_now_until_date = forms.DateField(
        label="Active from Now Until Date", widget=forms.DateInput(attrs={"class": "datepicker"}), required=False
    )
    status = forms.ModelMultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        queryset=AllocationStatusChoice.objects.all().order_by(Lower("name")),
        required=False,
    )
    show_all_allocations = forms.BooleanField(initial=False, required=False)


class AllocationReviewUserForm(forms.Form):
    ALLOCATION_REVIEW_USER_CHOICES = (
        ("keep_in_allocation_and_project", "Keep in allocation and project"),
        ("keep_in_project_only", "Remove from this allocation only"),
        ("remove_from_project", "Remove from project"),
    )

    username = forms.CharField(max_length=150, disabled=True)
    first_name = forms.CharField(max_length=150, required=False, disabled=True)
    last_name = forms.CharField(max_length=150, required=False, disabled=True)
    email = forms.EmailField(max_length=100, required=False, disabled=True)
    user_status = forms.ChoiceField(choices=ALLOCATION_REVIEW_USER_CHOICES)


class AllocationInvoiceNoteDeleteForm(forms.Form):
    pk = forms.IntegerField(required=False, disabled=True)
    note = forms.CharField(widget=forms.Textarea, disabled=True)
    author = forms.CharField(max_length=512, required=False, disabled=True)
    selected = forms.BooleanField(initial=False, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pk"].widget = forms.HiddenInput()


class AllocationAccountForm(forms.ModelForm):
    class Meta:
        model = AllocationAccount
        fields = [
            "name",
        ]


class AllocationAttributeChangeForm(forms.Form):
    pk = forms.IntegerField(required=False, disabled=True)
    name = forms.CharField(max_length=150, required=False, disabled=True)
    value = forms.CharField(max_length=150, required=False, disabled=True)
    new_value = forms.CharField(max_length=150, required=False, disabled=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pk"].widget = forms.HiddenInput()

    def clean(self):
        cleaned_data = super().clean()

        if cleaned_data.get("new_value") != "":
            allocation_attribute = AllocationAttribute.objects.get(pk=cleaned_data.get("pk"))
            allocation_attribute.value = cleaned_data.get("new_value")
            allocation_attribute.clean()


class AllocationAttributeUpdateForm(forms.Form):
    change_pk = forms.IntegerField(required=False, disabled=True)
    attribute_pk = forms.IntegerField(required=False, disabled=True)
    name = forms.CharField(max_length=150, required=False, disabled=True)
    value = forms.CharField(max_length=150, required=False, disabled=True)
    new_value = forms.CharField(max_length=150, required=False, disabled=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["change_pk"].widget = forms.HiddenInput()
        self.fields["attribute_pk"].widget = forms.HiddenInput()

    def clean(self):
        cleaned_data = super().clean()
        allocation_attribute = AllocationAttribute.objects.get(pk=cleaned_data.get("attribute_pk"))

        allocation_attribute.value = cleaned_data.get("new_value")
        allocation_attribute.clean()


class AllocationAttributeEditForm(forms.Form):
    attribute_pk = forms.IntegerField(required=False, disabled=True)
    name = forms.CharField(max_length=150, required=False, disabled=True)
    orig_value = forms.CharField(max_length=150, required=False, disabled=True)
    value = forms.CharField(max_length=150, required=False, disabled=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["attribute_pk"].widget = forms.HiddenInput()

    def clean(self):
        cleaned_data = super().clean()
        allocation_attribute = AllocationAttribute.objects.get(pk=cleaned_data.get("attribute_pk"))

        allocation_attribute.value = cleaned_data.get("value")
        allocation_attribute.clean()


class AllocationChangeForm(forms.Form):
    EXTENSION_CHOICES = [(0, "No Extension")]
    for choice in ALLOCATION_CHANGE_REQUEST_EXTENSION_DAYS:
        EXTENSION_CHOICES.append((choice, "{} days".format(choice)))

    end_date_extension = forms.TypedChoiceField(
        label="Request End Date Extension",
        choices=EXTENSION_CHOICES,
        coerce=int,
        required=False,
        empty_value=0,
    )
    justification = forms.CharField(
        label="Justification for Changes",
        widget=forms.Textarea,
        required=True,
        help_text="Justification for requesting this allocation change request.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class AllocationChangeNoteForm(forms.Form):
    notes = forms.CharField(
        max_length=512,
        label="Notes",
        required=False,
        widget=forms.Textarea,
        help_text="Leave any feedback about the allocation change request.",
    )


class AllocationAttributeCreateForm(forms.ModelForm):
    class Meta:
        model = AllocationAttribute
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super(AllocationAttributeCreateForm, self).__init__(*args, **kwargs)
        self.fields["allocation_attribute_type"].queryset = self.fields["allocation_attribute_type"].queryset.order_by(
            Lower("name")
        )
