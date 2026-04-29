#############################################################
# Copyright 2024 Lawrence Livermore National Security, LLC
# (c.f. AUTHORS, NOTICE.LLNS, COPYING)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
##############################################################

import concurrent
import glob
import os
import subprocess
import sys
import threading
import time
from collections import OrderedDict, defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import flux
import flux.importer
from flux.conf_builtin import conf_builtin_get
from flux.idset import IDset
from flux.utils import tomli as tomllib
from flux.utils.graphlib import TopologicalSorter

# ==============================================================================
# SECTION 1: Utility Functions
# ==============================================================================


def run_all_rc_scripts(runlevel):
    """
    Helper script for flux-modprobe(1) rc1 and rc3 scripts that replaces
    the following shell code from rc1/rc3:
    ```
    core_dir=$(cd ${0%/*} && pwd -P)
    all_dirs=$core_dir${FLUX_RC_EXTRA:+":$FLUX_RC_EXTRA"}
    IFS=:
    for rcdir in $all_dirs; do
        for rcfile in $rcdir/rc{runlevel}.d/*; do
        [ -e $rcfile ] || continue
            echo running $rcfile
            $rcfile || exit_rc=1
        done
    done
    ```

    Args:
        runlevel (int): runlevel (1 or 3) in which function is running
    Raises:
        OSError: one or more rc scripts failed
    """
    success = True
    core_dir = Path(conf_builtin_get("confdir")).resolve()
    all_dirs = [core_dir]
    rc_extra = os.environ.get("FLUX_RC_EXTRA")
    if rc_extra:
        all_dirs.extend(Path(d) for d in rc_extra.split(":") if d.strip())

    for entry in all_dirs:
        rcdir = entry / f"rc{runlevel}.d"
        if not rcdir.exists() or not rcdir.is_dir():
            continue
        try:
            # Get all files in rcX.d directory, sorted by name
            rc_files = sorted(
                [
                    file
                    for file in rcdir.iterdir()
                    if file.is_file() and os.access(file, os.X_OK)
                ]
            )

            # for rcfile in $rcdir/rc1.d/*; do
            for rcfile in rc_files:
                try:
                    print(f"running {rcfile}")
                    subprocess.run([str(rcfile)], check=True)
                except subprocess.CalledProcessError as e:
                    success = False
                    print(
                        f"{rcfile} failed with exit code {e.returncode}",
                        file=sys.stderr,
                    )
                except (FileNotFoundError, PermissionError, OSError) as e:
                    success = False
                    print(f"Cannot execute {rcfile}: {e}", file=sys.stderr)

        except (PermissionError, OSError) as e:
            success = False
            print(f"Cannot access directory {rcdir}: {e}", file=sys.stderr)

    if not success:
        raise OSError(f"one or more rc{runlevel}.d scripts failed")


def default_flux_confdir():
    """
    Return the builtin Flux confdir
    """
    return Path(conf_builtin_get("confdir"))


# ==============================================================================
# SECTION 2: Core Data Structures
# ==============================================================================


class RankConditional:
    """
    Conditional rank statement, e.g. ``>0``
    """

    def __init__(self, arg):
        if arg[0] == ">":
            self.gt = True
        elif arg[0] == "<":
            self.gt = False
        else:
            raise ValueError("rank condition must be either < or >")
        self.rank = int(arg[1:])

    def test(self, rank):
        if self.gt:
            return rank > self.rank
        return rank < self.rank

    def __str__(self):
        s = ">" if self.gt else "<"
        return f"{s}{self.rank}"


class RankIDset:
    """
    Rank by IDset, e.g. ``all`` or ``0-1``
    """

    def __init__(self, arg):
        self.ranks = None
        self.all = False
        if arg == "all":
            self.all = True
        else:
            try:
                self.ranks = IDset(arg)
            except ValueError:
                raise ValueError(f"ranks: invalid idset: {arg}")

    def test(self, rank):
        if self.all:
            return True
        return self.ranks[rank]

    def __str__(self):
        if self.all:
            return "all"
        return f"{self.ranks}"


def rank_conditional(arg):
    """
    Rank conditional factory function
    """
    cls = RankIDset
    if arg.startswith((">", "<")):
        cls = RankConditional
    return cls(arg)


class TaskDB:
    """
    Task database supporting service alternatives and priority-based selection.

    Structure: {service: {task_name: TaskEntry(priority, index, task)}}

    Tasks are stored in a dict-of-dicts structure where each service maps to
    a dict of task names to entries. Each entry is a TaskEntry namedtuple with
    priority (int), insertion index (int), and task object. When selecting a
    task for a service, the highest priority enabled task is chosen. If no
    enabled tasks exist, the highest priority task overall is returned
    regardless of enabled status.
    """

    TaskEntry = namedtuple("TaskEntry", ["priority", "index", "task"])

    def __init__(self):
        # {service: {task_name: TaskEntry(priority, index, task)}}
        self._services = defaultdict(dict)
        self._insertion_counter = 0

    def add(self, task: "Task", index: int = None) -> None:
        """Add task to database for its name and all services it provides"""
        if index is None:
            index = self._insertion_counter
            self._insertion_counter += 1
        entry = self.TaskEntry(task.priority, index, task)
        for service in (task.name, *task.provides):
            self._services[service][task.name] = entry

    def get(self, service: str) -> "Task":
        """
        Return the highest priority task providing ``service`` which is not
        disabled. If there are no non-disabled tasks providing ``service``,
        then return the highest priority task regardless of disabled status.
        If no tasks provide ``service``, raise ``ValueError``.

        Note: Only checks the `disabled` flag, not the full `enabled()` method
        which requires context for rank/config/attr checks.
        """
        if service not in self._services or len(self._services[service]) == 0:
            raise ValueError(f"no such task or module {service}")

        tasks = self._services[service]
        # Find non-disabled tasks with highest (priority, index)
        not_disabled = {
            name: entry for name, entry in tasks.items() if not entry.task.disabled
        }
        if not not_disabled:
            # Return highest priority task even if disabled
            return max(tasks.values(), key=lambda e: (e.priority, e.index)).task
        return max(not_disabled.values(), key=lambda e: (e.priority, e.index)).task

    def get_all(self, service: str) -> list:
        """
        Return all tasks providing ``service``, sorted by (priority, index).

        Args:
            service: Service or task name to look up

        Returns:
            List of Task objects sorted from lowest to highest priority.
            Empty list if service doesn't exist.
        """
        if service not in self._services:
            return []
        tasks = self._services[service]
        # Sort by (priority, index) ascending
        sorted_entries = sorted(tasks.values(), key=lambda e: (e.priority, e.index))
        return [e.task for e in sorted_entries]

    def get_entry(self, service: str, task_name: str):
        """
        Get TaskEntry for a specific task providing a service.

        Args:
            service: Service name
            task_name: Task name

        Returns:
            TaskEntry with priority, index, and task

        Raises:
            ValueError: If service or task not found
        """
        if service not in self._services:
            raise ValueError(f"no such service {service}")
        if task_name not in self._services[service]:
            raise ValueError(f"task {task_name} does not provide {service}")
        return self._services[service][task_name]

    def update(self, task: "Task") -> None:
        """
        Update an existing task in the database, or add it if not found.

        Updates the task object in place, preserving the original insertion
        order. Handles updates to priority, provides list, and other attributes.

        WARNING: If the task does not exist, it will be added automatically.
        Use has() first if you need strict update-only semantics.

        Args:
            task: Task object to update (identified by task.name)
        """
        # First check if task exists in any service
        found = False
        for service in self._services:
            if task.name in self._services[service]:
                found = True
                break

        if not found:
            # Task doesn't exist yet, add it
            self.add(task)
            return

        # Update all services where this task should appear
        for service in (task.name, *task.provides):
            if service in self._services and task.name in self._services[service]:
                old_entry = self._services[service][task.name]
                # Preserve insertion order but update priority and task
                self._services[service][task.name] = self.TaskEntry(
                    task.priority,
                    old_entry.index,
                    task,
                )
            else:
                # New service added to provides, add entry with preserved index
                # Get the insertion index from any existing service
                for existing_service in self._services:
                    if task.name in self._services[existing_service]:
                        index = self._services[existing_service][task.name].index
                        entry = self.TaskEntry(task.priority, index, task)
                        self._services[service][task.name] = entry
                        break

    def set_alternative(self, service: str, name: str, propagate: bool = True) -> None:
        """Select a specific alternative 'name' for service"""
        if service not in self._services:
            raise ValueError(f"no such service {service}")
        if name not in self._services[service]:
            raise ValueError(f"no module {name} provides {service}")

        tasks = self._services[service]
        # nothing to do if only one alternative
        if len(tasks) == 1:
            return

        # Find max priority and bump selected alternative above it
        max_priority = max(e.priority for e in tasks.values())
        entry = tasks[name]
        tasks[name] = self.TaskEntry(max_priority + 1, entry.index, entry.task)

        # Propagate to other services this task provides
        if propagate:
            task = entry.task
            for other_service in task.provides:
                if other_service != service:
                    self.set_alternative(other_service, name, propagate=False)

    def disable(self, service: str) -> None:
        """Disable all tasks providing this task/module/service"""
        if service not in self._services or not self._services[service]:
            raise ValueError(f"no such module or task '{service}'")
        for entry in self._services[service].values():
            entry.task.disabled = True

    def enable(self, service: str) -> None:
        """
        Force a module/task/service to be enabled even if it would normally
        be disabled by rank, needs-config, or needs-attr.
        """
        if service not in self._services or not self._services[service]:
            raise ValueError(f"no such module or task '{service}'")
        for entry in self._services[service].values():
            entry.task.force_enabled = True

    def has(self, service: str) -> bool:
        """
        Check if a task/module/service exists in the database.

        More efficient than calling get() and catching ValueError.
        """
        return service in self._services and len(self._services[service]) > 0

    def has_enabled_provider(self, tasks, service: str) -> bool:
        """
        Check if any non-disabled task in tasks provides the given service.

        Args:
            tasks: Iterable of task names to check
            service: Service name to look for

        Returns:
            True if at least one non-disabled task provides service
        """
        for x in tasks:
            task = self.get(x)
            if not task.disabled and service in (task.name, *task.provides):
                return True
        return False


class DependencySolver:
    """
    Handles all dependency resolution for modprobe tasks.

    This class encapsulates the complex logic for resolving task dependencies,
    including:
    - Finding all required dependencies (requires)
    - Filtering tasks based on needs constraints
    - Building execution order precedence graphs (before/after)
    - Finding safely removable modules

    Separated from Modprobe class for clarity and testability.
    """

    def __init__(self, taskdb, context):
        """
        Initialize dependency solver.

        Args:
            taskdb: TaskDB instance for task lookup
            context: Context instance for checking enabled status
        """
        self.taskdb = taskdb
        self.context = context

    def resolve_service(self, service: str, ignore_needs: bool = False):
        """
        Resolve service name to actual task, considering needs constraints.

        Returns the highest priority task providing `service` that:
        1. Is enabled (passes enabled() check with context)
        2. Has all its needs satisfied (unless ignore_needs=True)

        Falls back to highest priority task if no viable tasks exist.

        Args:
            service: Service or task name to resolve
            ignore_needs: If True, skip needs checking (for explicit loads)

        Returns:
            Task object

        Raises:
            ValueError: If service doesn't exist in taskdb
        """
        candidates = self.taskdb.get_all(service)
        if not candidates:
            raise ValueError(f"no such task or module {service}")

        # Find viable candidates (enabled + needs satisfied)
        viable = []
        for task in candidates:
            if not task.enabled(self.context):
                continue
            if ignore_needs or self._needs_satisfied(task):
                viable.append(task)

        if viable:
            # Return highest priority viable task
            # Use TaskEntry priority (respects set_alternative bumps), not Task.priority
            def priority_key(t):
                entry = self.taskdb.get_entry(service, t.name)
                return (entry.priority, entry.index)

            return max(viable, key=priority_key)

        # Fallback: return highest priority task even if not viable
        return candidates[-1]  # get_all returns sorted, so last is highest

    def _needs_satisfied(self, task, checking=None) -> bool:
        """
        Check if all of task's needs are satisfiable.

        A need is satisfiable if there exists an enabled task providing
        that service whose needs are also satisfied (checked recursively).

        Args:
            task: Task to check
            checking: Set of task names currently being checked (prevents cycles)

        Returns:
            True if all needs are satisfied, False otherwise
        """
        if checking is None:
            checking = set()

        if task.name in checking:
            return False  # Circular dependency

        checking.add(task.name)

        for need in task.needs:
            if not self._has_enabled_provider(need, checking):
                return False

        return True

    def _has_enabled_provider(self, service: str, checking: set) -> bool:
        """
        Check if any enabled task with satisfied needs provides this service.

        Args:
            service: Service name to check
            checking: Set of task names being checked (prevents cycles)

        Returns:
            True if an enabled provider with satisfied needs exists
        """
        candidates = self.taskdb.get_all(service)
        for task in candidates:
            if not task.enabled(self.context):
                continue
            if task.name in checking:
                continue  # Skip if we're already checking this task
            if self._needs_satisfied(task, checking):
                return True
        return False

    def solve_requirements(self, tasks, ignore_disabled=False) -> list:
        """
        Recursively find all requirements of tasks.

        Args:
            tasks: Iterable of task names to solve
            ignore_disabled: If True, include disabled tasks in result

        Returns:
            List of task names including all required dependencies.
            Disabled tasks are skipped unless ignore_disabled=True.
            Does not modify input.
        """
        result = self._solve_requirements_impl(tasks, set(), set(), ignore_disabled)
        return list(result)

    def _solve_requirements_impl(self, tasks, visited, skipped, ignore_disabled):
        """
        Internal recursive implementation of solve_requirements.

        Args:
            tasks: Iterable of task names to solve
            visited: Set of already-visited tasks (prevents infinite recursion)
            skipped: Set of skipped (disabled) tasks
            ignore_disabled: If True, include disabled tasks in result

        Returns:
            Set of task names including all required dependencies
        """
        result = set()
        to_visit = [x for x in tasks if x not in visited]

        for name in to_visit:
            # Use resolve_service to get the right task (considering needs)
            task = self.resolve_service(name, ignore_needs=ignore_disabled)
            if ignore_disabled or task.enabled(self.context):
                result.add(task.name)
            else:
                skipped.add(task.name)
            visited.add(task.name)
            if task.requires:
                rset = self._solve_requirements_impl(
                    tasks=task.requires,
                    visited=visited,
                    skipped=skipped,
                    ignore_disabled=ignore_disabled,
                )
                result.update(rset)

        return result

    def solve_needs(self, tasks) -> list:
        """
        Filter out tasks where needs constraints are not met.

        When a task is removed because a needed service is not available,
        all tasks that need it are also recursively removed.

        Args:
            tasks: Iterable of task names

        Returns:
            New list of task names with unsatisfied needs removed.
            Does not modify input.
        """
        # Work on a copy to avoid mutating caller's data
        tasks_list = list(tasks)
        removed = set()

        def mark_for_removal(task_name):
            """Recursively mark task and its dependents for removal"""
            if task_name in removed or task_name not in tasks_list:
                return

            removed.add(task_name)

            # Find what this task provides
            task = self.resolve_service(task_name, ignore_needs=False)
            provides_set = set((task.name, *task.provides))

            # Mark all tasks that need this task for removal
            for name in tasks_list:
                if name not in removed:
                    x = self.resolve_service(name, ignore_needs=False)
                    if not provides_set.isdisjoint(x.needs):
                        mark_for_removal(name)

        # Check each task's needs
        for name in tasks_list:
            if name in removed:
                continue
            task = self.resolve_service(name, ignore_needs=False)
            for need in task.needs:
                if not self.taskdb.has_enabled_provider(tasks_list, need):
                    mark_for_removal(name)
                    break

        # Return new list with removed tasks filtered out
        return [name for name in tasks_list if name not in removed]

    def solve_execution_order(self, tasks) -> dict:
        """
        Build precedence graph for tasks based on before/after constraints.

        Args:
            tasks: List/set of task names

        Returns:
            Dict mapping task names to list of predecessor task names

        Note: If tasks is a set, a copy is made internally to avoid mutating
        the input. Lists are always converted to sets internally.
        """
        if not isinstance(tasks, set):
            tasks = set(tasks)
        else:
            tasks = set(tasks)  # Make a copy to avoid mutating caller's set
        deps = {}

        # Cache resolve_service calls to avoid repeated lookups
        resolve_cache = {}

        def resolve_cached(name):
            if name not in resolve_cache:
                resolve_cache[name] = self.resolve_service(name, ignore_needs=False)
            return resolve_cache[name]

        # Ensure tasks set contains all provides and the actual task name
        # (since presence in the set determines if a task is included in
        # the predecessor list below)
        provides = set()
        for task in tasks:
            # Use resolve_service to get the right task (considering needs)
            task = resolve_cached(task)
            provides.add(task.name)
            provides.update(task.provides)
        tasks.update(provides)

        for name in tasks:
            task = resolve_cached(name)
            if "*" in task.after:
                # Add all tasks to deps (except those that also specify "*"
                # in their 'after' list)
                resolved_tasks = [(x, resolve_cached(x)) for x in tasks]
                deps[task.name] = [
                    t.name for x, t in resolved_tasks if "*" not in t.after
                ]
            else:
                after_tasks = [resolve_cached(x).name for x in task.after]
                deps[task.name] = [x for x in after_tasks if x in tasks]

        # Process before constraints
        self._process_before(tasks, deps, resolve_cache)

        return deps

    def _process_before(self, tasks, deps, resolve_cache=None):
        """
        Process task.before constraints by appending to successor predecessor lists.

        Args:
            tasks: Set of task names
            deps: Dict of task names to predecessor lists (modified in place)
            resolve_cache: Optional dict cache for resolve_service results
        """
        if resolve_cache is None:
            resolve_cache = {}

        def resolve_cached(name):
            if name not in resolve_cache:
                resolve_cache[name] = self.resolve_service(name, ignore_needs=False)
            return resolve_cache[name]

        def deps_add_all(name):
            """Add name as a predecessor to all entries in deps"""
            for task in [resolve_cached(x) for x in deps.keys()]:
                if "*" not in task.before:
                    deps[task.name].append(name)

        for name in tasks:
            task = resolve_cached(name)
            for successor in task.before:
                if successor == "*":
                    deps_add_all(task.name)
                else:
                    # resolve real successor name:
                    successor = resolve_cached(successor).name
                    if successor in deps:
                        deps[successor].append(task.name)

    def get_requires(self, tasks) -> dict:
        """
        Get forward requires dependency map for tasks.

        Args:
            tasks: Iterable of task names

        Returns:
            Dict mapping each task name to list of tasks it requires
        """
        deps = {}
        for name in tasks:
            task = self.resolve_service(name, ignore_needs=False)
            deps[task.name] = list(task.requires)
        return deps

    def get_reverse_requires(self, tasks) -> dict:
        """
        Get reverse requires dependency map for tasks.

        Args:
            tasks: Iterable of task names

        Returns:
            Dict mapping each task name to set of tasks that require it
        """
        rdeps = {}
        for name in tasks:
            task = self.resolve_service(name, ignore_needs=False)
            for req in task.requires:
                if req not in rdeps:
                    rdeps[req] = set()
                rdeps[req].add(task.name)
        return rdeps

    def solve_removal(self, dependencies: dict, modules_to_remove) -> list:
        """
        Find modules that can be safely removed.

        Given a set of modules to remove and their dependency lists, finds
        additional modules that can be removed because they no longer have
        any dependents.

        Args:
            dependencies: Dict of modules to their dependency list
            modules_to_remove: Iterable of modules to remove

        Returns:
            New list of modules that can be safely removed (includes original
            modules plus cascaded removals). Does not modify inputs.

        Raises:
            ValueError: If any module to remove still has dependents
        """
        # Build reverse dependency map
        dependents = {}
        for dependent, reqs in dependencies.items():
            for req in reqs:
                if req not in dependents:
                    dependents[req] = set()
                dependents[req].add(dependent)

        # Start with the items we're told to remove
        removed_items = set(modules_to_remove)
        result = list(modules_to_remove)

        # Keep track of items to check in this iteration
        modules_to_check = set(modules_to_remove)

        while modules_to_check:
            next_modules_to_check = set()

            for removed_item in modules_to_check:
                # Find all dependencies of the removed item (items it depended on)
                if removed_item in dependencies:
                    for dependency in dependencies[removed_item]:
                        # Skip if this dependency is already being removed
                        if dependency in removed_items:
                            continue

                        # Check if this dependency still has other items depending on it
                        remaining_dependents = (
                            dependents.get(dependency, set()) - removed_items
                        )

                        # If no remaining dependents, it can be removed
                        if not remaining_dependents:
                            removed_items.add(dependency)
                            result.append(dependency)
                            next_modules_to_check.add(dependency)

            modules_to_check = next_modules_to_check

        # Check if any removed modules still have dependents
        # (build a clean view of dependents with removed items filtered out)
        for name in result:
            remaining = dependents.get(name, set()) - removed_items
            # Also filter out by real task name in case of aliases
            try:
                self.taskdb.get(name)  # Verify task exists
                remaining = {
                    dep
                    for dep in remaining
                    if dep not in removed_items
                    and self.taskdb.get(dep).name not in removed_items
                }
            except ValueError:
                # Task doesn't exist in taskdb (e.g., nonexistent module)
                # Just use the remaining set as-is
                pass
            if remaining:
                raise ValueError(
                    f"{name} still in use by " + ", ".join(sorted(remaining))
                )

        return result


class ConfigLoader:
    """
    Handles configuration and RC file loading for modprobe.

    This class encapsulates the logic for:
    - Building searchpaths from environment variables and config
    - Locating TOML configuration files
    - Locating Python RC script files
    - Expanding .d directories in the searchpath

    Separated from Modprobe class for clarity and testability.
    """

    def __init__(self, searchpath, print_func):
        """
        Initialize configuration loader.

        Args:
            searchpath: Dict of {"toml": [paths...], "py": [paths...]}
            print_func: Function to call for debug output
        """
        self.searchpath = searchpath
        self.print = print_func

    def get_toml_files(self):
        """
        Return all modprobe config toml files found in the following order:
         - Always read ``{fluxdatadir}/modprobe/modprobe.toml``
         - for dir in self.searchpath: read ``{dir}/modprobe.d/*.toml``

        Returns:
            List of absolute paths to TOML files
        """
        files = []
        builtin_toml_config = (
            Path(conf_builtin_get("datadir")) / "modprobe" / "modprobe.toml"
        )
        self.print(f"checking {builtin_toml_config}")
        if builtin_toml_config.exists():
            files.append(str(builtin_toml_config))
        files.extend(self._searchpath_expand())
        return files

    def get_rc_files(self, name="rc1"):
        """
        Return all modprobe rc *.py files found in the following order:
         - Always read ``{fluxdatadir}/modprobe/{name}.py`` (e.g. ``rc1.py``)
         - for dir in self.searchpath: read ``{dir}/{name}.d/*.py``

        Args:
            name: RC file basename (e.g., "rc1", "rc3")

        Returns:
            List of absolute paths to Python RC files
        """
        files = []
        builtin_rc_file = (
            Path(conf_builtin_get("libexecdir")) / "modprobe" / f"{name}.py"
        )
        self.print(f"checking {builtin_rc_file}")
        if builtin_rc_file.exists():
            files.append(str(builtin_rc_file))
        files.extend(self._searchpath_expand(name=name, ext="py"))
        return files

    def _searchpath_expand(self, name="modprobe", ext="toml"):
        """
        Expand searchpath for extension ``ext`` based on configured paths.

        Args:
            name: Base name for .d directory (e.g., "modprobe", "rc1")
            ext: File extension to search for (e.g., "toml", "py")

        Returns:
            List of absolute paths to files found
        """
        files = []
        for directory in self.searchpath[ext]:
            self.print(f"checking {directory}/{name}.d/*.{ext}")
            if Path(directory).exists():
                files.extend(sorted(glob.glob(f"{directory}/{name}.d/*.{ext}")))
        return files

    @staticmethod
    def build_searchpath(builtindir="datadir"):
        """
        Build searchpath list from environment variables and config.

        Returns list of dirs in ``FLUX_MODPROBE_PATH`` if set, otherwise
        returns the default modprobe search path.

        Args:
            builtindir: base path for builtin/package path. Should
                be either "datadir" or "libexecdir".

        Returns:
            List of directory paths (duplicates removed)
        """
        searchpath = []
        if "FLUX_MODPROBE_PATH" in os.environ:
            searchpath = filter(
                lambda s: s and not s.isspace(),
                os.environ["FLUX_MODPROBE_PATH"].split(":"),
            )
        else:
            pkgdir = conf_builtin_get(builtindir)
            confdir = conf_builtin_get("confdir")
            searchpath = [f"{pkgdir}/modprobe", f"{confdir}/modprobe"]

        if "FLUX_MODPROBE_PATH_APPEND" in os.environ:
            searchpath.extend(
                filter(
                    lambda s: s and not s.isspace(),
                    os.environ["FLUX_MODPROBE_PATH_APPEND"].split(":"),
                )
            )

        # return searchpath without duplicates
        return list(OrderedDict.fromkeys(searchpath))


# ==============================================================================
# SECTION 3: Task Definitions
# ==============================================================================


class Task:
    """
    Class representing a modprobe task and associated configuration
    """

    VALID_ARGS = {
        "ranks": "all",
        "provides": [],
        "requires": [],
        "needs": [],
        "before": [],
        "after": [],
        "needs_attrs": [],
        "needs_config": [],
        "needs_env": [],
        "disabled": False,
        "priority": 100,
    }

    def __init__(self, name, *args, **kwargs):
        self.name = name
        self.starttime = None
        self.endtime = None
        self.force_enabled = False

        for attr in kwargs:
            if attr not in self.VALID_ARGS:
                raise ValueError(f"{self.name}: unknown task argument {attr}")

        for attr, default in self.VALID_ARGS.items():
            val = kwargs.get(attr, default)
            # Handle case where attr is set explicitly to None, in which case,
            # inherit the default
            if val is None:
                val = default
            setattr(self, attr, val)

        # convert self.ranks to rank conditional object:
        self.ranks = rank_conditional(self.ranks)

        if "*" in self.before and self.after:
            raise ValueError(
                f"{self.name}: cannot specify 'before=[\"*\"]' "
                f"when 'after' is also set (after={self.after})"
            )
        if "*" in self.after and self.before:
            raise ValueError(
                f"{self.name}: cannot specify 'after=[\"*\"]' "
                f"when 'before' is also set (before={self.before})"
            )

    @staticmethod
    def _check_spec(spec, getter):
        """
        Check if an identifier is set or unset based on an input ``spec``
        and a ``getter`` function which should return the value of a ``spec``
        (e.g. a config key or broker attribute) or None if the spec is
        unset.

        If ``spec`` begins with ``!``, then this function returns True only
        if getter returns None for ``spec[1:]``. Otherwise, this function
        returns False if the getter returns None for ``spec``.

        Examples:
          _check_spec("foo", getter) -> True if getter("foo") returns non-None
          _check_spec("!foo", getter) -> True if getter("foo") returns None
        """
        inverted = spec.startswith("!")
        attr = spec[1:] if inverted else spec
        value = getter(attr)
        return value is None if inverted else value is not None

    def enabled(self, context=None):
        """
        Return True if task is currently not disabled. A task may be
        disabled by configuration, because it only runs on a given set of
        ranks, if the task has been configured to require a configuration
        or broker attribute which is not set, or if a module this task
        needs is not enabled.
        """
        if self.force_enabled:
            return True
        if context is None:
            return not self.disabled
        if self.disabled or not self.ranks.test(context.rank):
            return False
        for key in self.needs_config:
            if not self._check_spec(key, context.handle.conf_get):
                return False
        for attr in self.needs_attrs:
            if not self._check_spec(attr, context.attr_get):
                return False
        for var in self.needs_env:
            if not self._check_spec(var, context.getenv):
                return False
        return True

    def runtask(self, context):
        """
        Run this task's run() method (or dry_run() if dry_run is True)
        """
        self.starttime = time.time()
        try:
            if context.dry_run:
                self.dry_run(context)
            else:
                self.run(context)
        finally:
            self.endtime = time.time()

    def run(self, context):
        """
        A task's run() method. This should be overridden in the specific
        Task subclass.
        """
        print(self.name)

    def dry_run(self, context):
        """
        Default task dry_run() method. This prints the task name. Override
        in a subclass with more specific information if necessary.
        """
        print(self.name)


class CodeTask(Task):
    """
    A modprobe task that runs as a Python function
    """

    def __init__(self, name, func, *args, **kwargs):
        self.func = func
        super().__init__(name, *args, **kwargs)

    def run(self, context):
        context.print(f"start {self.name}")
        self.func(context)
        context.print(f"completed {self.name}")

    def dry_run(self, context):
        print(f"run {self.name}")


class Module(Task):
    """
    A modprobe task to load/remove a broker module.
    The default action is to the load the module. Call the ``set_remove()``
    method to convert the task to remove the module.
    """

    VALID_KEYS = (
        "name",
        "module",
        "args",
        "ranks",
        "provides",
        "requires",
        "needs",
        "before",
        "after",
        "needs-attrs",
        "needs-config",
        "needs-env",
        "priority",
        "disabled",
        "exec",
    )

    def __init__(self, conf):
        """Initialize a module task from modprobe.toml entry
        The default run method loads the module.
        Call set_remove() to set the task to unload a module.
        """
        try:
            name = conf["name"]
        except KeyError:
            raise ValueError("Missing required config key 'name'") from None

        self.module = conf.get("module", name)
        self.args = conf.get("args", [])
        self.exec = conf.get("exec", False)
        self.run = self._load

        # Build kwargs to pass along to Task class
        kwargs = {}
        for key, val in conf.items():
            if key not in self.VALID_KEYS:
                prefix = f"{self.name}: " if hasattr(self, "name") else ""
                raise ValueError(f"{prefix}invalid config key {key}")
            key = key.replace("-", "_")
            if key in super().VALID_ARGS:
                kwargs[key] = val

        super().__init__(name, **kwargs)

    def set_remove(self):
        """
        Mark module to be removed instead of loaded (the default)
        """
        # swap before and after
        self.after, self.before = self.before, self.after
        # clear needs and requires since these do not apply to module removal:
        self.needs = []
        self.requires = []
        self.run = self._remove

    def _load(self, context):
        args = context.getopts(self.name, default=self.args, also=self.provides)
        payload = {"path": self.module, "args": args, "exec": self.exec}

        if self.name != self.module:
            payload["name"] = self.name

        context.print(f"module.load {payload}")
        context.handle.rpc("module.load", payload).get()
        context.print(f"loaded {self.name}")

    def _remove(self, context):
        try:
            context.print(f"module.remove {self.name}")
            context.handle.rpc("module.remove", {"name": self.name}).get()
            context.print(f"removed {self.name}")
        except FileNotFoundError:
            # Ignore already unloaded modules
            pass

    def dry_run(self, context):
        if self.run == self._load:
            module_args = context.getopts(
                self.name, default=self.args, also=self.provides
            )
            print(" ".join([f"load {self.name}", *module_args]))
        else:
            print(f"remove {self.name}")

    def to_dict(self):
        return {
            attribute: getattr(self, attribute)
            for attribute in self.VALID_KEYS
            if hasattr(self, attribute)
        }


def task(name, **kwargs):
    """
    Decorator for modprobe "rc" task functions.

    This decorator is applied to functions in an rc1 or rc3 python
    source file to turn them into valid flux-modprobe(1) tasks.

    Args:
        name (required, str): The name of this task.
        ranks (optional, str): A rank expression that indicates on which
            ranks this task should be invoked. ``ranks`` may be a valid
            RFC 22 Idset string, a single integer prefixed with ``<`` or
            ``<`` to indicate matching ranks less than or greater than a
            given rank, or the string ``all`` (the default if ``ranks``
            is not specified). Examples: ``0``, ``>0``, ``0-3``.
        requires (optional, list): An optional list of task or module names
            this task requires. This is used to ensure required tasks are
            active when activating another task. It does not indicate that
            this task will necessarily be run before or after the tasks it
            requires. (See ``before`` or ``after`` for those features)
        needs (options, list): Disable this task if any task in ``needs`` is
            not active.
        provides (optional, list): An optional list of string service name
            that this task provides. This can be used to set up alternatives
            for a given service. (Mostly useful with modules)
        before (optional, list): A list of tasks or modules for which this task
            must be run before.
        after (optional, list) A list of tasks or modules for which this task
            must be run after.
        needs_attrs (optional, list): A list of broker attributes on which
            this task depends. If any of the attributes are not set then the
            task will not be run.
        needs_config (optional, list): A list of config keys on which this
            task depends. If any of the specified config keys are not set,
            then this task will not be run.
        needs_env (optional, list): A list of environment variables on which
            this task depends. If any of the specified environment variables
            are not set in the current environment, then this task will not
            be run.

    Example:
    ::
        # Declare a task that will be run after the kvs module is loaded
        # only on rank 0
        @task("test", ranks="0", needs=["kvs"], after=["kvs"])
        def test_kvs_task(context):
            # do something with kvs
    """
    if not isinstance(name, str):
        raise ValueError('task missing required name argument: @task("name")')

    def create_task(func):
        return CodeTask(name, func, **kwargs)

    return create_task


# ==============================================================================
# SECTION 4: Execution Context
# ==============================================================================


class Context:
    """
    Context object passed to all modprobe tasks.
    Allows the passage of data between tasks, simple access to broker
    configuration and attributes, addition of module arguments, etc.
    """

    tls = threading.local()

    def __init__(self, modprobe, verbose=False, dry_run=False):
        self.verbose = verbose
        self.dry_run = dry_run
        self.modprobe = modprobe
        self._data = {}
        self.module_args = defaultdict(list)
        self.module_args_overwrite = {}
        self._broker_env_cache = {}

    def print(self, *args):
        """Print message if modprobe is in verbose output mode"""
        if self.verbose:
            print(*args, file=sys.stderr)

    @property
    def handle(self):
        """Return a per-thread Flux handle created on demand"""
        if not hasattr(self.tls, "_handle"):
            self.tls._handle = flux.Flux()
        return self.tls._handle

    @property
    def rank(self):
        return self.handle.get_rank()

    def set(self, key, value):
        """Set arbitrary data at key for future use. (see get())"""
        self._data[key] = value

    def get(self, key, default=None):
        """Get arbitrary data set by other tasks with optional default value"""
        return self._data.get(key, default)

    def attr_get(self, attr, default=None):
        """Get broker attribute with optional default"""
        try:
            return self.handle.attr_get(attr)
        except FileNotFoundError:
            return default

    def conf_get(self, key, default=None):
        """Get config key with optional default"""
        return self.handle.conf_get(key, default=default)

    def _broker_getenv(self, var):
        """Get environment variable value from local broker. Cache result"""
        if var not in self._broker_env_cache:
            value = None
            try:
                result = self.handle.rpc("broker.getenv", {"names": [var]})
                value = result.get()["env"].get(var)
            except OSError:
                # treat error as envvar unset
                pass
            self._broker_env_cache[var] = value
        return self._broker_env_cache[var]

    def getenv(self, var, default=None):
        """Get env var value locally or from local broker"""
        value = os.environ.get(var)
        if value is None:
            value = self._broker_getenv(var)
        if value is None:
            return default
        return value

    def setenv(self, name_or_env, value=None):
        """Set or unset environment variables in the current process and broker.

        Variables set via this method that are not in the broker's env
        blocklist will be inherited by rc2 and rc3. A value of None
        causes the named variable to be unset.

        Note: concurrent calls from unrelated tasks running in parallel are
        safe in CPython since os.environ operations are serialized by the
        GIL.

        Args:
            name_or_env: a variable name string, or a dict mapping names
                to values. Values may be strings or None to unset.
            value: the value to set, when name_or_env is a string.

        Raises:
            ValueError: if any value is not a string or None.
            OSError: if the RPC fails.
        """
        if isinstance(name_or_env, dict):
            env = name_or_env
        else:
            env = {name_or_env: value}
        for name, val in env.items():
            if val is not None and not isinstance(val, str):
                raise ValueError(f"{name}: value must be a string or None")
        self.rpc("broker.setenv", {"env": env}).get()
        for name, val in env.items():
            # Note: old values of these variables may still be cached in
            # _broker_env_cache, but since getenv() checks the local
            # environment first, variables set here will always take
            # precedence over any cached broker values.
            if val is None:
                os.environ.pop(name, None)
                # Cache None as a negative entry so getenv() does not fall
                # back to a stale broker env value for this variable.
                self._broker_env_cache[name] = None
            else:
                os.environ[name] = val

    def rpc(self, topic, *args, **kwargs):
        """Convenience function to call context.handle.rpc()"""
        return self.handle.rpc(topic, *args, **kwargs)

    def setopt(self, module, options, overwrite=False):
        """
        Append option to module opts. ``option`` may contain multiple options
        separated by whitespace.
        """
        if overwrite:
            self.module_args_overwrite[module] = True

        self.module_args[module].extend(options.split())

    def getopts(self, name, default=None, also=None):
        """Get module opts for module 'name'
        If also is provided, append any module options for those names as well
        """
        lst = [name]
        if also is not None:
            lst.extend(also)
        result = []
        if default is not None and not self.module_args_overwrite.get(name):
            result = list(default)
        for name in lst:
            result.extend(self.module_args[name])
        return result

    def bash(self, command):
        """Execute command under ``bash -c``"""
        process = subprocess.run(["bash", "-c", command])
        if process.returncode != 0:
            if process.returncode > 0:
                raise RuntimeError(
                    f"bash: exited with exit status {process.returncode}"
                )
            else:
                raise RuntimeError(f"bash: died by signal {process.returncode}")

    def load_modules(self, modules):
        """Set a list of modules to load by name"""
        self.modprobe.activate_modules(modules)

    def remove_modules(self, modules=None):
        """
        Set a list of modules to remove by name.
        Remove all if ``modules`` is None.
        """
        self.modprobe.set_remove(modules)

    def set_alternative(self, name, alternative):
        """Force an alternative for module ``name`` to ``alternative``"""
        self.modprobe.taskdb.set_alternative(name, alternative)

    def enable(self, name):
        """
        Force enable a module/service/task, overriding ranks conditional,
        needs-config, and needs-attrs.

        Note: This will not also enable dependencies of ``name``.
        """
        self.modprobe.taskdb.enable(name)


class ModuleList:
    """Simple class for iteration and lookup of loaded modules"""

    def __init__(self, handle):
        resp = handle.rpc("module.list").get()
        self.loaded_modules = []
        self.servicemap = {}
        for entry in resp["mods"]:
            if entry["path"] != "builtin":
                self.loaded_modules.append(entry["name"])
                for name in entry["services"]:
                    self.servicemap[name] = entry["name"]

    def __iter__(self):
        for name in self.loaded_modules:
            yield name

    def lookup(self, name):
        return self.servicemap.get(name, None)


# ==============================================================================
# SECTION 5: Main Orchestrator
# ==============================================================================


class Modprobe:
    """
    The modprobe main class. Intended for use by flux-modprobe(1).
    """

    def __init__(self, timing=False, verbose=False, dry_run=False):
        self.exitcode = 0
        self.timing = None
        self.t0 = None
        self._locals = None

        self.taskdb = TaskDB()
        self.context = Context(self, verbose=verbose, dry_run=dry_run)
        self.handle = self.context.handle
        self.rank = self.handle.get_rank()

        # Initialize dependency solver
        self.solver = DependencySolver(self.taskdb, self.context)

        # Initialize configuration loader
        searchpath = {
            "toml": ConfigLoader.build_searchpath(),
            "py": ConfigLoader.build_searchpath(builtindir="libexecdir"),
        }
        self.loader = ConfigLoader(searchpath, self.print)
        self.searchpath = searchpath  # Keep for backward compatibility

        # Active tasks are those added via the @task decorator, and
        # which will be active by default when running "all" tasks:
        self._active_tasks = []

        if timing:
            self.timing = []
            self.t0 = time.time()

    @property
    def timestamp(self):
        if not self.t0:
            return 0.0
        return time.time() - self.t0

    @property
    def active_tasks(self):
        """Return all active, enabled tasks"""
        return self._process_needs(
            list(
                filter(
                    lambda task: self.get_task(task).enabled(self.context),
                    self._active_tasks,
                )
            )
        )

    def print(self, *args):
        """Wrapper for context.print()"""
        self.context.print(*args)

    def add_timing(self, name, starttime, end=None):
        if self.timing is None:
            return
        if end is None:
            end = self.timestamp
        self.timing.append(
            {"name": name, "starttime": starttime, "duration": end - starttime}
        )

    def save_task_timing(self, tasks):
        if self.timing is None:
            return
        for task in sorted(tasks, key=lambda x: x.starttime):
            self.add_timing(
                task.name,
                starttime=task.starttime - self.t0,
                end=task.endtime - self.t0,
            )

    def add_task(self, task):
        """Add a task to internal task db"""
        self.taskdb.add(task)

    def add_active_task(self, task):
        """Add a task to the task db and active tasks list"""
        # Only add to taskdb if it doesn't exist yet (to preserve priority
        # bumps from set_alternative() calls)
        if not self.has_task(task.name):
            self.add_task(task)
        self._active_tasks.append(task.name)

    def get_task(self, name, default=None):
        """
        Return task by name from taskdb.

        Note: This does NOT do service resolution. For service-aware lookup
        (e.g., "sched" -> actual scheduler module), use resolve_service().
        """
        return self.taskdb.get(name)

    def resolve_service(self, name, ignore_needs=False):
        """
        Resolve service name to actual task using needs-aware resolution.

        This is the public API for service resolution. It considers:
        - Task enabled/disabled status
        - Needs constraints (unless ignore_needs=True)
        - Priority and alternatives

        Args:
            name: Service or task name to resolve
            ignore_needs: If True, skip needs checking

        Returns:
            Task object that would be loaded for this service
        """
        return self.solver.resolve_service(name, ignore_needs)

    def has_task(self, name):
        """Return True if task exists in taskdb"""
        try:
            self.taskdb.get(name)
            return True
        except ValueError:
            return False

    def update_module(self, name, entry, new_module=None):
        task = self.get_task(name)
        if new_module is None:
            if "name" not in entry:
                entry["name"] = name
            new_module = Module(entry)
        for key in entry.keys():
            setattr(task, key, getattr(new_module, key))
        self.taskdb.update(task)

    def add_modules(self, file):
        with open(file, "rb") as fp:
            config = tomllib.load(fp)

        for name, entry in config.items():
            if name == "modules":
                for table in entry:
                    try:
                        task = Module(table)
                    except ValueError as exc:
                        raise ValueError(
                            f"{file}: invalid modules entry: {exc}"
                        ) from None

                    # Update tasks that already exist:
                    if self.has_task(task.name):
                        self.update_module(task.name, table, task)
                    else:
                        self.add_task(task)
            else:
                # Allow <module>.key to update an existing configured module:
                self.update_module(name, entry)

    def _update_modules_from_config(self):
        """Update modules using broker config
        Process a [modules] table in config support the following keys:

        alternatives: A table of keys that may adjust the current module
            alternative. e.g. ``alternatives.sched = "sched-simple"``
        <name>: A table of updates for an individual module, e.g.
            ``feasibility.ranks = "0,1"``
        """
        modules_conf = self.handle.conf_get("modules", default={})
        for key, entry in modules_conf.items():
            if key == "alternatives":
                for service, name in entry.items():
                    self.taskdb.set_alternative(service, name)
            else:
                self.update_module(key, entry)

    def configure_modules(self):
        """
        Load module configuration from TOML config.
        """
        for file in self.loader.get_toml_files():
            self.print(f"loading {file}")
            self.add_modules(file)

        self._update_modules_from_config()

        return self

    def set_alternative(self, name, alternative):
        """
        Force an alternative for module ``name`` to ``alternative``
        """
        self.taskdb.set_alternative(name, alternative)

    def disable(self, name):
        """
        Disable module/task ``name``
        """
        self.taskdb.disable(name)

    def _solve_tasks_recursive(self, tasks, visited=None, skipped=None):
        """Recursively find all requirements of 'tasks'"""
        # New solver API doesn't expose visited/skipped (private impl detail)
        # Legacy wrapper for backward compatibility if needed
        return self.solver.solve_requirements(tasks)

    def _process_needs(self, tasks):
        """Remove all tasks in tasks where task.needs is not met"""
        result = self.solver.solve_needs(tasks)
        # The new API returns a new list and doesn't call modprobe.disable().
        # We need to detect what was removed and disable those tasks.
        removed = set(tasks) - set(result)
        for name in removed:
            try:
                self.taskdb.disable(name)
            except (ValueError, KeyError):
                # Task may not exist or may be a provider alias
                pass
        return result

    def solve(self, tasks, timing=True, ignore_disabled=False):
        t0 = self.timestamp
        result = self.solver.solve_requirements(tasks, ignore_disabled=ignore_disabled)
        if timing:
            self.add_timing("solve", t0)
        return result

    def _process_before(self, tasks, deps):
        """Process any task.before by appending this task's name to all
        successor's predecessor list.
        """
        return self.solver._process_before(tasks, deps)

    def get_deps(self, tasks):
        """Return dependencies for tasks as dict of names to predecessor list"""
        t0 = self.timestamp
        deps = self.solver.solve_execution_order(tasks)
        self.add_timing("deps", t0)
        return deps

    def get_requires(self, tasks, reverse=False):
        """Return dependencies for tasks as dicts of names to dependencies"""
        if reverse:
            return self.solver.get_reverse_requires(tasks)
        return self.solver.get_requires(tasks)

    def run(self, deps):
        """Run all tasks in deps in precedence order"""
        t0 = self.timestamp
        sorter = TopologicalSorter(deps)
        sorter.prepare()
        self.add_timing("prepare", t0)

        max_workers = None
        if sys.version_info < (3, 8):
            # In Python < 3.8, idle threads are not reused up to
            # max_workers. For these versions, set a low max_workers
            # to force thread (and therefore Flux handle) reuse:
            max_workers = 5

        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = {}
        started = {}
        aborted = False

        while sorter.is_active():
            for task in [self.get_task(x) for x in sorter.get_ready()]:
                if task.name not in started:
                    if not aborted:
                        future = executor.submit(task.runtask, self.context)
                        started[task.name] = task
                        futures[future] = task
                    else:
                        # Do not run task, mark it done
                        sorter.done(task.name)

            done, not_done = concurrent.futures.wait(
                futures.keys(), return_when=concurrent.futures.FIRST_COMPLETED
            )

            for future in done:
                task = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"{task.name}: {exc}", file=sys.stderr)
                    self.exitcode = 1
                    aborted = True
                    # cancel any non-running but scheduled futures immediately
                    for x in not_done:
                        x.cancel()
                sorter.done(task.name)
                del futures[future]

        self.save_task_timing(started.values())
        executor.shutdown(wait=True)

        return self.exitcode

    def _load_file(self, path):
        module = flux.importer.import_path(path)
        tasks = filter(lambda x: isinstance(x, CodeTask), vars(module).values())
        for task in tasks:
            self.add_active_task(task)

        # Check for function setup() which should run before all other tasks
        setup = getattr(module, "setup", None)
        if callable(setup):
            setup(self.context)

    def read_rcfile(self, name):
        # For absolute file path, just add tasks from single file:
        if name.endswith(".py"):
            self.print(f"loading {name}")
            self._load_file(name)
            return

        # O/w, load all rc files in configured search path:
        for file in self.loader.get_rc_files(name):
            self.print(f"loading {file}")
            self._load_file(file)

    def activate_modules(self, modules):
        for module in modules:
            task = self.get_task(module)
            if not isinstance(task, Module):
                raise ValueError(f"{module} is not a module")
            self._active_tasks.append(module)
            # append any requires from this module
            for other in task.requires:
                self._active_tasks.append(other)

    def _set_all_alternatives(self, modules):
        # Set all modules as the current selected alternatives:
        for module in modules:
            try:
                task = self.get_task(module)
            except ValueError:
                # Module not in taskdb (e.g., disabled or not configured)
                continue
            for service in task.provides:
                self.set_alternative(service, task.name)

    def load(self, modules):
        """
        Load modules and their dependencies (if not already loaded)

        Args:
            modules (list): List of modules to load.

        Raises:
            FileExistsError: Target modules (and all their dependencies)
                are already loaded, so there is nothing to do.

        Note:
            This method uses ignore_disabled=True to allow loading modules
            that are disabled by configuration. This enables explicit loading
            of non-default alternatives or disabled modules.
        """
        mlist = ModuleList(self.handle)
        needed_modules = [
            x for x in self.solve(modules, ignore_disabled=True) if x not in mlist
        ]

        # Ensure explicitly requested modules are the current alternatives
        self._set_all_alternatives(needed_modules)

        if needed_modules:
            self.run(self.get_deps(needed_modules))
        else:
            raise FileExistsError(
                "All modules and their dependencies are already loaded."
            )

    def _find_removable(self, dependencies, modules_to_remove):
        """
        Given a set of modules and dependency list of all modules, find modules
        that can be removed because they no longer have any dependents.

        Args:
            dependencies (dict): Dictionary of modules to dependency list
            modules_to_remove (list): List of modules to remove

        Returns:
            list: modules that can be safely removed (including original list)
        """
        return self.solver.solve_removal(dependencies, modules_to_remove)

    def _solve_modules_remove(self, modules=None):
        """Solve for a set of currently loaded modules to remove"""
        mlist = ModuleList(self.handle)
        all_modules = [x for x in mlist if self.has_task(x)]

        if not modules or "all" in modules:
            # remove all configured modules
            modules = all_modules
        else:
            # Check if all specified modules are loaded:
            for module in modules:
                if not mlist.lookup(module):
                    raise ValueError(f"module {module} is not loaded")

        modules = self._find_removable(self.get_requires(all_modules), modules)

        # Compute reverse precedence graph of modules to remove so that
        # they can be removed in reverse order of load:
        deps = self.get_deps(modules)
        rdeps = defaultdict(set)
        for name, deplist in deps.items():
            for mod in deplist:
                mod = mlist.lookup(mod)
                rdeps[mod].add(name)

        # Convert module names to ModuleRemove tasks:
        tasks = set()
        for service in modules:
            name = mlist.lookup(service)
            if name is not None:
                tasks.add(name)

        # filter out tasks from rdeps that are not slated for removal
        deps = {}
        for name in tasks:
            deps[name] = {x for x in rdeps[name] if x in tasks}

        return list(tasks), deps

    def set_remove(self, modules=None):
        """Register a set of modules to remove or remove all modules"""
        if modules is None:
            mlist = ModuleList(self.handle)
            modules = [x for x in mlist if self.has_task(x)]

        # When removing modules, always set available alternatives to
        # the specific modules being requested to remove. This prevents
        # non-loaded but default alternatives from appearing in get_deps()
        # later:
        self._set_all_alternatives(modules)

        for module in modules:
            task = self.get_task(module)
            task.set_remove()
            self.add_active_task(task)

    def remove(self, modules):
        """Remove loaded modules"""
        tasks, deps = self._solve_modules_remove(modules)
        [self.get_task(x).set_remove() for x in deps.keys()]
        self.run(deps)
