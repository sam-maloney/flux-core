################################################
Integrating Software/Hardware Products with Flux
################################################

This is a landing page for vendors tasked with integrating their products
with the Flux Framework.

Overview of Flux
================

Flux is a workload manager built from a distributed message broker that can be
launched standalone, under another resource manager, or recursively within
itself.  For a general orientation, start with the :doc:`flux-core
documentation <../index>`, which introduces the framework and links to guides
for starting an instance and interacting with it.

Because a single-user Flux instance starts anywhere without special privilege,
Flux fits naturally into converged and cloud environments as well as
traditional HPC clusters, and it composes with Kubernetes in both directions.
The `Flux Operator <https://flux-framework.org/flux-operator/>`_ runs Flux
inside a Kubernetes cluster, while `flux-usernetes
<https://github.com/converged-computing/flux-usernetes>`_ runs user-space
Kubernetes as a job under Flux.  Other framework projects extend Flux for these
settings; the :doc:`flux-core documentation <../index>` lists the key ones.

Comparison with Slurm
=====================

Flux covers much of the same ground as Slurm and can also run alongside it.
:doc:`admin_slurm` compares the two and outlines a migration path, while
:ref:`start_slurm` shows how to run Flux as a step manager inside a Slurm
allocation.

Contacting Flux Developers
==========================

The Flux development team tries to be responsive to queries on github, which
is the preferred means of contact.  Feel free to open an issue or discussion
in `flux-core <https://github.com/flux-framework/flux-core>` to get questions
answered or vet ideas.

Background for Flux plugin developers
=====================================

Most product integrations take the form of components that hook into Flux at
well-defined points.  :ref:`background_components` shows where these fit in the
architecture.

New services can be added as broker modules, which run as threads inside the
broker and are loaded with :man1:`flux-module`; these are traditionally
written in C, but Flux also supports
:ref:`Python broker modules <python_broker_modules>`, which run as separate
processes and are thus safer.  These may may be the quickest path for vendor
prototyping.

Two other common plugin extension points are the job manager, documented
in :man7:`flux-jobtap-plugins`, and the job shell, documented in
:man7:`flux-shell-plugins`.  :doc:`internals` collects further developer
resources.

Integrations that touch Flux wire protocols, data formats, or the job schema
should consult the :doc:`Flux RFC specifications <rfc:index>`, which are the
authoritative references for these interfaces.

Licensing and development practices
===================================

Flux-core is free software licensed under LGPL-3.0-only, and the wider framework is
developed in the open on `GitHub <https://github.com/flux-framework>`_ under
the Collective Code Construction Contract described in :doc:`RFC 1
<rfc:spec_1>`.  Vendors are encouraged to follow the same model for their
integrations.

Where licensing permits, hosting an integration as a repository under the
`flux-framework <https://github.com/flux-framework>`_ organization has real
advantages: it keeps the code visible to the Flux maintainers, who can flag
uses of unstable interfaces before they break; it invites review and
contributions from the broader community; and it ensures the work outlives any
single procurement.  Open development also lets vendor and laboratory engineers
co-develop and test against real systems, as was done for the flux-coral2
project described below.

Even when a full open-source model is not possible, the practices RFC 1
codifies (small reviewed pull requests, public issue tracking, and continuous
integration) apply equally well to a vendor's own repositories.

AI coding assistants
====================

The Flux project encourages the use of AI coding assistants for integration
work.  They can accelerate learning an unfamiliar codebase and drafting
plugins and broker modules.  However, :doc:`RFC 1 <rfc:spec_1>` is explicit
that a human Contributor takes full responsibility for every patch including
correctness, quality, and license compliance, regardless of whether an
assistant was used.  In practice this means being prepared to understand and
defend in review anything an assistant proposes; unreviewed generated code is
not acceptable simply because a tool produced it.

Two conventions follow from this:

- An assistant SHOULD NOT be credited as an author or co-author (for example
  with a ``Co-authored-by`` trailer), because authorship implies a
  responsibility only a human can hold.

- Where an assistant was used, the commit message SHOULD record it with an
  ``Assisted-by:`` trailer of the form ``Assisted-by: NAME:MODEL_VERSION``,
  for example ``Assisted-by: Claude:claude-opus-4.8``.

Example integration
===================

`flux-coral2 <https://github.com/flux-framework/flux-coral2>`_ is a repository
co-developed with HPE and LLNL to support the El Capitan system procurement,
and serves as a working example of integrating vendor hardware and software
with Flux.
