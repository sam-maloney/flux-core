#!/usr/bin/env python3
###############################################################
# Copyright 2024 Lawrence Livermore National Security, LLC
# (c.f. AUTHORS, NOTICE.LLNS, COPYING)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
###############################################################

import unittest

import subflux  # noqa: F401
from flux.modprobe import Task, TaskDB
from pycotap import TAPTestRunner


class TestTaskDB(unittest.TestCase):
    """Test TaskDB implementation"""

    def test_add_task_basic(self):
        """Add a task and retrieve it by name"""
        db = TaskDB()
        task = Task("test-task")
        db.add(task)
        retrieved = db.get("test-task")
        self.assertEqual(retrieved.name, "test-task")
        self.assertIs(retrieved, task)

    def test_add_task_with_provides(self):
        """Task provides multiple services"""
        db = TaskDB()
        task = Task("module-a", provides=["service-x", "service-y"])
        db.add(task)

        # Should be retrievable by name
        self.assertIs(db.get("module-a"), task)
        # Should be retrievable by any provides
        self.assertIs(db.get("service-x"), task)
        self.assertIs(db.get("service-y"), task)

    def test_get_nonexistent_raises(self):
        """Getting nonexistent service raises ValueError"""
        db = TaskDB()
        with self.assertRaises(ValueError) as ctx:
            db.get("nonexistent")
        self.assertIn("no such task or module", str(ctx.exception))

    def test_get_highest_priority(self):
        """Multiple alternatives - picks highest priority"""
        db = TaskDB()
        task_low = Task("module-a", provides=["service"], priority=10)
        task_high = Task("module-b", provides=["service"], priority=100)
        task_medium = Task("module-c", provides=["service"], priority=50)

        db.add(task_low)
        db.add(task_high)
        db.add(task_medium)

        # Should return highest priority
        retrieved = db.get("service")
        self.assertEqual(retrieved.name, "module-b")
        self.assertEqual(retrieved.priority, 100)

    def test_get_prefers_enabled(self):
        """Picks enabled task over higher priority disabled task"""
        db = TaskDB()
        task_high = Task("module-a", provides=["service"], priority=100)
        task_low = Task("module-b", provides=["service"], priority=10)

        db.add(task_high)
        db.add(task_low)

        # Disable the high priority task
        task_high.disabled = True

        # Should return lower priority enabled task
        retrieved = db.get("service")
        self.assertEqual(retrieved.name, "module-b")
        self.assertEqual(retrieved.priority, 10)

    def test_get_insertion_order_tiebreaker(self):
        """When priorities equal, later insertion wins"""
        db = TaskDB()
        task_first = Task("module-a", provides=["service"], priority=100)
        task_second = Task("module-b", provides=["service"], priority=100)

        db.add(task_first)
        db.add(task_second)

        # Should return later insertion when priorities equal
        retrieved = db.get("service")
        self.assertEqual(retrieved.name, "module-b")

    def test_update_preserves_order(self):
        """Update doesn't change insertion order"""
        db = TaskDB()
        task_first = Task("module-a", provides=["service"], priority=50)
        task_second = Task("module-b", provides=["service"], priority=100)

        db.add(task_first)
        db.add(task_second)

        # Update first task priority but not above second
        task_first.priority = 75
        db.update(task_first)

        # Second should still win due to insertion order
        retrieved = db.get("service")
        self.assertEqual(retrieved.name, "module-b")

        # Update first task priority above second
        task_first.priority = 150
        db.update(task_first)

        # Now first should win due to priority
        retrieved = db.get("service")
        self.assertEqual(retrieved.name, "module-a")

    def test_set_alternative(self):
        """Selecting alternative bumps priority"""
        db = TaskDB()
        task_a = Task("module-a", provides=["service"], priority=10)
        task_b = Task("module-b", provides=["service"], priority=20)
        task_c = Task("module-c", provides=["service"], priority=15)

        db.add(task_a)
        db.add(task_b)
        db.add(task_c)

        # Initially, module-b should win (highest priority)
        self.assertEqual(db.get("service").name, "module-b")

        # Select module-a as alternative
        db.set_alternative("service", "module-a")

        # Now module-a should win (priority bumped above max)
        self.assertEqual(db.get("service").name, "module-a")

    def test_set_alternative_propagates(self):
        """Setting alternative propagates to all provides"""
        db = TaskDB()
        task_a = Task("module-a", provides=["svc-x", "svc-y"], priority=10)
        task_b = Task("module-b", provides=["svc-x", "svc-y"], priority=20)

        db.add(task_a)
        db.add(task_b)

        # Select module-a for svc-x (should propagate to svc-y)
        db.set_alternative("svc-x", "module-a")

        # Both services should now return module-a
        self.assertEqual(db.get("svc-x").name, "module-a")
        self.assertEqual(db.get("svc-y").name, "module-a")

    def test_set_alternative_no_propagate(self):
        """Setting alternative with propagate=False only affects one service"""
        db = TaskDB()
        task_a = Task("module-a", provides=["svc-x", "svc-y"], priority=10)
        task_b = Task("module-b", provides=["svc-x", "svc-y"], priority=20)

        db.add(task_a)
        db.add(task_b)

        # Select module-a for svc-x without propagation
        db.set_alternative("svc-x", "module-a", propagate=False)

        # Only svc-x should return module-a
        self.assertEqual(db.get("svc-x").name, "module-a")
        # svc-y should still return module-b
        self.assertEqual(db.get("svc-y").name, "module-b")

    def test_set_alternative_nonexistent_service(self):
        """Setting alternative for nonexistent service raises"""
        db = TaskDB()
        with self.assertRaises(ValueError) as ctx:
            db.set_alternative("nonexistent", "module-a")
        self.assertIn("no such service", str(ctx.exception))

    def test_set_alternative_nonexistent_module(self):
        """Setting alternative to nonexistent module raises"""
        db = TaskDB()
        task = Task("module-a", provides=["service"])
        db.add(task)

        with self.assertRaises(ValueError) as ctx:
            db.set_alternative("service", "nonexistent")
        self.assertIn("no module nonexistent provides", str(ctx.exception))

    def test_disable_task(self):
        """Disabling affects get()"""
        db = TaskDB()
        task_a = Task("module-a", provides=["service"])
        task_b = Task("module-b", provides=["service"])

        db.add(task_a)
        db.add(task_b)

        # Disable all tasks providing service
        db.disable("service")

        # Both should be disabled
        self.assertTrue(task_a.disabled)
        self.assertTrue(task_b.disabled)

        # get() should still return highest priority (even if disabled)
        result = db.get("service")
        self.assertIn(result.name, ["module-a", "module-b"])

    def test_enable_task(self):
        """Force enable overrides conditions"""
        db = TaskDB()
        task = Task("module-a", disabled=True)
        db.add(task)

        # Task is disabled
        self.assertTrue(task.disabled)

        # Force enable
        db.enable("module-a")

        # Should now be force-enabled
        self.assertTrue(task.force_enabled)

    def test_has_enabled_provider(self):
        """has_enabled_provider returns True if any non-disabled task provides service"""
        db = TaskDB()
        task_a = Task("module-a", provides=["service-x"])
        task_b = Task("module-b", provides=["service-y"])

        db.add(task_a)
        db.add(task_b)

        # Should find service-x
        self.assertTrue(db.has_enabled_provider(["module-a", "module-b"], "service-x"))
        # Should find service-y
        self.assertTrue(db.has_enabled_provider(["module-a", "module-b"], "service-y"))
        # Should not find nonexistent
        self.assertFalse(
            db.has_enabled_provider(["module-a", "module-b"], "nonexistent")
        )

    def test_has_enabled_provider_disabled_task(self):
        """has_enabled_provider returns False for disabled tasks"""
        db = TaskDB()
        task = Task("module-a", provides=["service"])
        task.disabled = True
        db.add(task)

        # Should not find service from disabled task
        self.assertFalse(db.has_enabled_provider(["module-a"], "service"))

    def test_has(self):
        """has() returns True if task/service exists"""
        db = TaskDB()
        task = Task("module-a", provides=["service-x"])
        db.add(task)

        # Should find by name
        self.assertTrue(db.has("module-a"))
        # Should find by provides
        self.assertTrue(db.has("service-x"))
        # Should not find nonexistent
        self.assertFalse(db.has("nonexistent"))

    def test_enable_does_not_cascade_to_requires(self):
        """Enable does not cascade to required tasks (by design)"""
        db = TaskDB()
        task_a = Task("module-a", requires=["module-b"], disabled=True)
        task_b = Task("module-b", disabled=True)

        db.add(task_a)
        db.add(task_b)

        # Enable module-a
        db.enable("module-a")

        # module-a should be force-enabled
        self.assertTrue(task_a.force_enabled)
        # module-b should NOT be force-enabled (by design)
        self.assertFalse(task_b.force_enabled)
        self.assertTrue(task_b.disabled)

    def test_disable_with_needs_semantics(self):
        """Disabling a task affects tasks that need it (handled by Modprobe)"""
        # Note: The cascading disable for 'needs' is handled in
        # Modprobe._process_needs(), not in TaskDB.
        # TaskDB.disable() only disables the specific task.
        db = TaskDB()
        task_a = Task("module-a")
        task_b = Task("module-b", needs=["module-a"])

        db.add(task_a)
        db.add(task_b)

        # Disable module-a at TaskDB level
        db.disable("module-a")

        # module-a is disabled
        self.assertTrue(task_a.disabled)
        # module-b is NOT automatically disabled by TaskDB
        # (that logic lives in Modprobe._process_needs)
        self.assertFalse(task_b.disabled)


if __name__ == "__main__":
    unittest.main(testRunner=TAPTestRunner())


# vi: ts=4 sw=4 expandtab
