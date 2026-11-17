# Razor views and `web.config`

**Status: planned, not implemented.**

## The problem

C# support covers `.cs` files and `appsettings*.json`. An ASP.NET project also
has Razor views (`.cshtml`), Razor components (`.razor`) and, in the older
framework, `web.config`. Shorwatch does not read any of these. Views are
counted as *Razor* in the "not analyzed" table of a report, so a view with an
RSA call in a code block is never passed over in silence. `web.config` is not
counted yet: it is found by its name, not its extension, which the table does
not handle.

## What it would do

1. **Say it.** Views are already listed as not analyzed; `web.config` is
   still to be added to that table, which needs to match a file by name.
2. **Then read the C# inside views.** A Razor file is HTML with C# in code
   blocks (`@{ ... }`, `@code { ... }`, `@functions`) and expressions
   (`@Model.Algorithm`). A frontend would extract that C# and hand it to the
   existing C# machinery, keeping the line and column in the original file.
3. **`web.config`.** Settings that name algorithms, such as the machine key's
   validation and decryption algorithms, become properties the config rules can
   match.

## How it would fit

- The Razor frontend reuses the C# lowering rather than duplicating it: the
  work is the extraction and the position mapping.
- `web.config` is XML; the build-file frontends already read XML safely, with
  bounded nesting and no external entities.
- Rules for `web.config` go under the config platform, like the other
  configuration formats.

## Left out

- Compiling views, or resolving what a tag helper generates.
- `.aspx` and WebForms.

## Undecided

- How much of a view is worth extracting: code blocks only, or inline
  expressions too.
