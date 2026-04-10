# SPDX-FileCopyrightText: (C) ColdFront Authors
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from coldfront.core.allocation.models import Allocation
from coldfront.core.resource.models import ResourceAttribute, ResourceAttributeType, ResourceType
from coldfront.core.test_helpers.factories import (
    AAttributeTypeFactory,
    AllocationAttributeFactory,
    AllocationAttributeTypeFactory,
    AllocationStatusChoiceFactory,
    ProjectFactory,
    ResourceFactory,
    ResourceTypeFactory,
)
from coldfront.plugins.slurm.associations import SlurmCluster


class AssociationTest(TestCase):
    @classmethod
    def setUpClass(cls):
        call_command("add_default_project_choices")
        call_command("add_allocation_defaults")
        call_command("add_resource_defaults")

        super(AssociationTest, cls).setUpClass()

    @classmethod
    def setUpTestData(cls):
        # create cluster resource
        cls.cluster_res = ResourceFactory(resource_type=ResourceType.objects.get(name="Cluster"))
        ResourceAttribute.objects.create(
            resource=cls.cluster_res,
            resource_attribute_type=ResourceAttributeType.objects.get(name="slurm_cluster"),
            value="test_cluster",
        )
        # create qos resource
        cls.qos_res = ResourceFactory(resource_type=ResourceTypeFactory(name="Cluster QOS"), name="Quality of Service")
        # create project
        cls.project = ProjectFactory(title="test_proj")
        # create allocations
        alloc_kwargs = {"project": cls.project, "status": AllocationStatusChoiceFactory(name="Active")}
        text_aat = AAttributeTypeFactory(name="Text")
        sqn_aat = AllocationAttributeTypeFactory(name="slurm_qos_name", attribute_type=text_aat)
        sqa_aat = AllocationAttributeTypeFactory(name="slurm_qos_specs", attribute_type=text_aat)
        cls.qfree = Allocation.objects.create(**alloc_kwargs)
        cls.qt1 = Allocation.objects.create(**alloc_kwargs)
        cls.qt2 = Allocation.objects.create(**alloc_kwargs)
        cls.qt3 = Allocation.objects.create(**alloc_kwargs)
        cls.qadmin = Allocation.objects.create(**alloc_kwargs)
        cls.qproj = Allocation.objects.create(**alloc_kwargs)
        cls.qfree.resources.add(cls.qos_res)
        cls.qt1.resources.add(cls.qos_res)
        cls.qt2.resources.add(cls.qos_res)
        cls.qt3.resources.add(cls.qos_res)
        cls.qadmin.resources.add(cls.qos_res)
        cls.qproj.resources.add(cls.qos_res)
        # slurm qos names
        aat_kwargs = {"allocation_attribute_type": sqn_aat}
        AllocationAttributeFactory(allocation=cls.qfree, value="free", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qt1, value="qos_tier1", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qt2, value="qos_tier2", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qt3, value="qos_tier3", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qadmin, value="qos_admin", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qproj, value="proj_myproj", **aat_kwargs)
        # slurm qos attributes
        aat_kwargs = {"allocation_attribute_type": sqa_aat}
        AllocationAttributeFactory(allocation=cls.qfree, value="Description='Added as default'", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qt1, value="Priority=1000", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qadmin, value="Description='qos_admin'", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qproj, value="Description='proj_myproj'", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qproj, value="GrpTRESMins=billing=1000", **aat_kwargs)
        AllocationAttributeFactory(allocation=cls.qproj, value="Flags='DenyOnLimit,NoDecay'", **aat_kwargs)

        cls.cluster_dump = StringIO("""
# To edit this file start with a cluster line for the new cluster
# Cluster - 'cluster_name':MaxNodesPerJob=50
# Followed by Accounts you want in this fashion (root is created by default)...
# Parent - 'root'
# Account - 'cs':MaxNodesPerJob=5:MaxJobs=4:MaxTRESMins=cpu=20:FairShare=399:MaxWallDuration=40:Description='Computer Science':Organization='LC'
# Any of the options after a ':' can be left out and they can be in any order.
# If you want to add any sub accounts just list the Parent THAT HAS ALREADY 
# BEEN CREATED before the account line in this fashion...
# Parent - 'cs'
# Account - 'test':MaxNodesPerJob=1:MaxJobs=1:MaxTRESMins=cpu=1:FairShare=1:MaxWallDuration=1:Description='Test Account':Organization='Test'
# To add users to a account add a line like this after a Parent - 'line'
# User - 'lipari':MaxNodesPerJob=2:MaxJobs=3:MaxTRESMins=cpu=4:FairShare=1:MaxWallDurationPerJob=1
QOS - 'free':Description='Added as default'
QOS - 'qos_tier1':Priority=1000
QOS - 'qos_tier2'
QOS - 'qos_tier3'
QOS - 'qos_admin':Description='qos_admin'
QOS - 'proj_myproj':Description='proj_myproj':GrpTRESMins=billing=1000:Flags='DenyOnLimit,NoDecay'
Cluster - 'test_cluster':Fairshare=1:QOS='free'
Parent - 'root'
User - 'root':DefaultAccount='root':AdminLevel='Administrator':Fairshare=1
        """)

    def expected_cluster(self, cluster):
        self.assertEqual(cluster.name, "test_cluster")
        self.assertEqual(len(cluster.qoses), 6)
        self.assertEqual(
            {qos_name for qos_name in cluster.qoses},
            {"free", "qos_tier1", "qos_tier2", "qos_tier3", "qos_admin", "proj_myproj"},
        )
        self.assertEqual(set(cluster.qoses["free"].specs), {"Description='Added as default'"})
        self.assertEqual(set(cluster.qoses["qos_tier1"].specs), {"Priority=1000"})
        self.assertEqual(len(cluster.qoses["qos_tier2"].specs), 0)
        self.assertEqual(len(cluster.qoses["qos_tier3"].specs), 0)
        self.assertEqual(set(cluster.qoses["qos_admin"].specs), {"Description='qos_admin'"})
        self.assertEqual(
            set(cluster.qoses["proj_myproj"].specs),
            {
                "Description='proj_myproj'",
                "GrpTRESMins=billing=1000",
                "Flags='DenyOnLimit,NoDecay'",
            },
        )

    def test_slurm_from_resource(self):
        cluster = SlurmCluster.new_from_resource(self.cluster_res)
        self.expected_cluster(cluster)

    def test_slurm_dump_roundtrip(self):
        """create from resource, dump, and load dump"""
        cluster = SlurmCluster.new_from_resource(self.cluster_res)
        out = StringIO("")
        cluster.write(out)
        out.seek(0)

        cluster = SlurmCluster.new_from_stream(out)

        self.expected_cluster(cluster)
        self.assertEqual(len(cluster.accounts), 1)
        self.assertIn("root", cluster.accounts)

    def test_slurm_from_stream(self):
        cluster = SlurmCluster.new_from_stream(self.cluster_dump)
        self.expected_cluster(cluster)
        self.assertEqual(len(cluster.accounts), 1)
        self.assertIn("root", cluster.accounts)
