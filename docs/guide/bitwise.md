# Bitwise operations

`Ipe.Bitwise` treats an `Int` as a fixed-width vector of bits and gives you the
boolean algebra over it: `and`, `or`, `xor`, `complement`, and the three shifts.
It is the tool for packing a set of flags into one integer, masking fields out of
a word, or any place a value is really a bag of independent bits rather than a
number.

## The mental model

Three knots.

- **Every operation is total.** `and`, `or`, `xor`, `complement`,
  `shiftLeftBy`, `shiftRightBy`, and `shiftRightZfBy` return an `Int` for any
  input — no failure, no `Maybe`, no allocation. They are pure arithmetic on the
  bit pattern, so they compose freely in an expression with no `<-` and no error
  to handle.
- **`Int` is 64-bit two's-complement.** `complement` flips all 64 bits, and a
  shift amount is taken modulo the word width. This is wider than the 32-bit
  convention some languages use, so a mask you build with `shiftLeftBy 40 1` is a
  real bit, not an overflow.
- **The two right shifts differ in the sign bit.** `shiftRightBy` is arithmetic:
  it replicates the sign bit, so a negative number stays negative. `shiftRightZfBy`
  is logical (zero-fill): it shifts a `0` into the top, so the result is always
  non-negative. Reach for the zero-fill shift when the `Int` is a bit pattern, not
  a signed magnitude.

## A worked example: a permission set

The example under
[`examples/shapes/script/bitwise-flags`](../../examples/shapes/script/bitwise-flags/src/Main.ipe)
packs three capabilities — read, write, execute — into the low bits of one `Int`,
then grants, tests, and revokes them.

Each capability is a single-bit mask, built by shifting `1` into position:

```ipe
read =
    Bitwise.shiftLeftBy 0 1

write =
    Bitwise.shiftLeftBy 1 1

execute =
    Bitwise.shiftLeftBy 2 1
```

Granting a capability is OR (union the bits); testing membership is AND compared
against the mask (every bit of the mask is set); revoking is AND with the
complement (clear that bit, leave the rest):

```ipe
grant a b =
    Bitwise.or a b

has mask flags =
    Bitwise.and flags mask == mask

revoke mask flags =
    Bitwise.and flags (Bitwise.complement mask)
```

Running it (`ipe dev run`) shows a set built up and then narrowed:

```
read|write   -> read write -
read|write|x -> read write exec
revoke write -> read - exec
```

## The why

Bitwise operations are the low-level escape hatch, so the design goal is that
they be [predictable][principles] and total: a bit operation never fails, so it
never forces an error path, and its result depends only on its inputs. Fixing
`Int` at a documented 64-bit width rather than leaving it platform-dependent is
the same predictability — a mask means the same thing wherever the program runs.

For most code that models a *set*, the typed [Set](set.md) or a record of `Bool`
fields is clearer than a packed integer — the field names document themselves and
the compiler checks them. Reach for `Bitwise` when the packing itself matters: a
wire format, a hardware register, a hash mix, or interop with a bit-encoded
protocol.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Bitwise` — `and`, `or`, `xor`,
  `complement`, and the shifts, each with a verified example.
- **Sibling guides:** [Sets](set.md) — the typed alternative when you really want
  a set, not a bit-packing. [Math](math.md) — arithmetic on `Int` and `Float`
  when the value is a number, not a bit vector. [Bytes](bytes.md) — raw octet
  sequences when the data is bytes rather than a single word.
