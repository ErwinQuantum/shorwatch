# More languages

**Status: planned, not implemented.**

## The problem

Shorwatch reads Java, Kotlin and C#. A repository in another language is not
analyzed, and every report says so (*not analyzed*, by language). A tool for
migrating cryptography has to cover where the cryptography is.

## What is needed for one language

Adding a language is bounded work, because most of the machinery is shared:

1. **A frontend**: a tree-sitter grammar and a traversal that lowers the file
   into the common representation (calls, constructions, constants, imports).
2. **A platform and rules**: the library APIs of that ecosystem, as YAML, with
   fixtures and a clean file per library.
3. **A dependency reader** for its package manifest, for the library inventory.
4. **Data flow.** The shared resolver handles values through variables,
   parameters and returns across files. A language with a different
   import or scoping model needs its own phase one, as C# did.

## Candidates

| Language | Why | Hard part |
|---|---|---|
| Python | The most common language for scripts and services that call crypto libraries | Dynamic typing: the type of a receiver is often unknown |
| Go | Standard-library crypto, widely used in infrastructure | Packages instead of classes |
| TypeScript and JavaScript | Web crypto and Node | Two languages, many import styles |
| F# and Visual Basic | The rest of .NET, which already has the rules | Two more grammars over the same libraries |

No order is decided. A language gets built when a real project needs it.

## Left out

- Compiled binaries and bytecode call sites. Shorwatch reads source, with one
  exception: it can read declarations from compiled Java dependencies to type
  calls.

## Undecided

- How to report dynamically typed code honestly: a call whose receiver's type
  is unknown is either a possible false positive or a missed finding.
