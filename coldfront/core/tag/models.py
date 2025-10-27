# SPDX-FileCopyrightText: (C) ColdFront Authors
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from django.db import models
from django.urls import reverse
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel
from taggit.models import GenericTaggedItemBase, TagBase
from treenode.models import TreeNodeModel


class Tag(TimeStampedModel, TagBase, TreeNodeModel):
    # TODO: I don't like how this is done, but it makes the most sense for ColdFront right now.
    html_classes = models.CharField(
        max_length=255,
        blank=True,
        help_text="Overriden by children. Meant for applying colors to tags. Bootstrap color docs: https://getbootstrap.com/docs/4.6/utilities/colors/",
        verbose_name="HTML classes",
    )
    description = models.CharField(
        verbose_name="description",
        max_length=200,
        blank=True,
    )
    object_types = models.ManyToManyField(
        to="contenttypes.ContentType",
        related_name="+",
        blank=True,
        help_text="The object type(s) to which this tag can be applied.",
    )

    # TODO: update when we have a more robust permissions system
    user_permissions = models.CharField(
        choices=[("none", "None"), ("view", "View"), ("edit", "Edit")],
        help_text="None: users cannot view, add, or remove this tag. View: users can only view this tag. Edit: users can view, add, or remove this tag.",
        max_length=32,
        default="none",
    )

    treenode_display_field = "name"

    class Meta:
        verbose_name = "tag"
        verbose_name_plural = "tags"

    def get_absolute_url(self):
        return reverse("extras:tag", args=[self.pk])

    # @property
    # def docs_url(self):
    #     return f"{settings.STATIC_URL}docs/models/extras/tag/"

    def slugify(self, tag, i=None):
        # Allow Unicode in Tag slugs (avoids empty slugs for Tags with all-Unicode names)
        slug = slugify(tag, allow_unicode=True)
        if i is not None:
            slug += "_%d" % i
        return slug


class TaggedItem(GenericTaggedItemBase):
    tag = models.ForeignKey(to=Tag, related_name="%(app_label)s_%(class)s_items", on_delete=models.CASCADE)

    # objects = RestrictedQuerySet.as_manager()

    class Meta:
        indexes = [models.Index(fields=["content_type", "object_id"])]
        verbose_name = _("tagged item")
        verbose_name_plural = _("tagged items")
        # Note: while there is no ordering applied here (because it would basically be done on fields
        # of the related `tag`), there is an ordering applied to extras.api.views.TaggedItemViewSet
        # to allow for proper pagination.
