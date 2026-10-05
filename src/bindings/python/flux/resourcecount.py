###############################################################
# Copyright 2026 Lawrence Livermore National Security, LLC
# (c.f. AUTHORS, NOTICE.LLNS, COPYING)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
###############################################################

import json
import numbers

from _flux._resourcecount import ffi, lib
from flux.wrapper import Wrapper, WrapperPimpl

COUNT_MAX = lib.COUNT_MAX
COUNT_INVALID_VALUE = lib.COUNT_INVALID_VALUE
COUNT_FLAG_SHORT = lib.COUNT_FLAG_SHORT
COUNT_FLAG_BRACKETS = lib.COUNT_FLAG_BRACKETS


class ResourceCountIterator:
    def __init__(self, count):
        self._count = count
        self._next = count.first

    def __iter__(self):
        return self

    def __next__(self):
        if self._next == COUNT_INVALID_VALUE * self._count.scale_factor:
            raise StopIteration
        result = self._next
        self._next = self._count.next(result)
        return result


class ResourceCount(WrapperPimpl):
    """A Flux jobspec resource count

    The ResourceCount class wraps libresourcecount, and represents the count
    key of a jobspec resource object. A resource count is one of a simple
    integer, an RFC 14 range, or an RFC 22 idset. See count_decode(3).

    A Python ResourceCount object may be created from a string such as
    "4", "2-8", "2-8:2:*", or "1,7-9", from an integer, or from a dict
    of the form used by a JSON parsed jobspec, e.g. {"min": 2, "max": 8}.
    For example:

    >>> print(ResourceCount("4"))
    4
    >>> print(ResourceCount(4))
    4
    >>> print(ResourceCount({"min": 2, "max": 8}))
    2-8

    Iteration yields every value the resource count may take, from first() up
    to and including last(). ResourceCounts which are unbounded ("2+") iterate
    up to the last valid value before COUNT_INVALID_VALUE * scale_factor.

    """

    class InnerWrapper(Wrapper):
        def __init__(
            self,
            arg="",
            handle=None,
        ):
            if handle is None:
                handle = lib.count_decode(arg.encode("utf-8"))
                if handle == ffi.NULL:
                    raise ValueError(f"ResourceCount(): Invalid argument: {arg}")
            super().__init__(
                ffi,
                lib,
                match=ffi.typeof("struct count *"),
                prefixes=["count_", "COUNT_"],
                destructor=lib.count_destroy,
                handle=handle,
            )

    def __init__(self, arg="", flags=COUNT_FLAG_SHORT, handle=None):
        super().__init__()
        if isinstance(arg, ResourceCount):
            arg = str(arg)
        elif isinstance(arg, dict):
            arg = json.dumps(arg)
        elif isinstance(arg, numbers.Integral):
            arg = str(int(arg))

        self.default_flags = flags
        self.scale_factor = 1
        try:
            self.pimpl = self.InnerWrapper(arg=arg, handle=handle)
        except (TypeError, AttributeError):
            raise TypeError(
                f"ResourceCount() expected a count string, integer, or dict, got {type(arg)}"
            )

    def __str__(self):
        return self.encode()

    def __repr__(self):
        return f"ResourceCount('{self.encode()}')"

    def __iter__(self):
        return ResourceCountIterator(self)

    def set_flags(self, flags):
        """Set default flags for ResourceCount encoding:
        valid flags are COUNT_FLAG_SHORT and COUNT_FLAG_BRACKETS
        """
        self.default_flags = flags

    def encode(self, flags=None):
        """Encode a ResourceCount to a string.
        :param: flags: (optional) flags to influence encoding
        """
        if flags is None:
            flags = self.default_flags
        #
        #  N.B. Do not use automatic wrapper call here to avoid leaking
        #  `char *` result. Instead, explicitly call free() after copying
        #  the returned string to Python
        #
        val = lib.count_encode(self.handle, flags)
        if val == ffi.NULL:
            raise ValueError(f"ResourceCount.encode(): Invalid flags: {flags}")
        result = ffi.string(val)
        lib.free(val)
        return result.decode("utf-8")

    @property
    def is_discrete(self):
        """True if the count specifies discrete values rather than a range

        The SHORT encoding of a simple count contains neither a comma nor a
        colon ("4", "2-8", "1-3", "2+"), while a count with gaps encodes as
        "1,7-9" and a stepped count as "2-8:2:*".
        """
        text = self.encode(flags=COUNT_FLAG_SHORT)
        return "," in text or ":" in text

    @staticmethod
    def _check_integer(i, name):
        if not isinstance(i, numbers.Integral):
            raise TypeError(f"ResourceCount.{name} supports integers, not {type(i)}")
        if i < 0:
            raise ValueError(f"negative integer passed to ResourceCount.{name}")

    @property
    def first(self):
        """Return the first (minimum) valid value that the count may take"""
        return self.pimpl.first() * self.scale_factor

    @property
    def last(self):
        """Return the last (maximum) valid value that the count may take
        Returns None for an unbounded range
        """
        last = self.pimpl.last()
        return last * self.scale_factor if last != COUNT_MAX else None

    def next(self, i):
        """Return the next value that the count may take after value i"""
        self._check_integer(i, "next")
        return self.pimpl.next(i // self.scale_factor) * self.scale_factor

    def scale(self, factor):
        """Scale the values of the count by an integer factor"""
        self._check_integer(factor, "next")
        self.scale_factor = factor
        return self


def decode(string):
    """Decode a count string and return ResourceCount object"""
    return ResourceCount(string)
