# Peerward independent-development boundary

Peerward is an independent implementation based on public standards and the
requirements frozen in `spec/`.  Production implementers must not consult any
pre-existing implementation of this product category while authoring code.

## Roles

- The specification role may study observable product behavior and public
  standards, then writes neutral requirements without source-level structure.
- The implementation role may read only this repository, language and library
  documentation, RFCs, and other public standards.
- The audit role may compare repositories after implementation but must not
  provide source excerpts to the implementation role.

## Isolation

Implementation must run in a fresh context.  Its filesystem view must contain
this repository and toolchain caches, but no reference repository.  No source,
tests, comments, documentation prose, assets, commit history, identifiers, or
directory layout may be copied from another product.

Generated files, standard license text, protocol names defined by standards,
and idiomatic build metadata are excluded from textual-similarity gates.

## Public wording

Peerward is described as "an independent implementation built on open
standards."  Do not claim that its authors have never seen another overlay
network product.
