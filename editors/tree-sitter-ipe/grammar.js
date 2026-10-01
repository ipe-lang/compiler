/**
 * tree-sitter grammar for Ipê.
 *
 * Mirrors the compiler's hand-written parser (the SSOT):
 *   - tokens/keywords/operators: src/compiler/parse/src/lexer.rs
 *   - declaration/expression/pattern/type forms: src/compiler/syntax/src/ast.rs
 *   - recursive-descent shape: src/compiler/parse/src/parser.rs
 *
 * Layout: Ipê is indentation-significant (src/compiler/parse/src/layout.rs),
 * but a tree-sitter grammar for highlighting does not reconstruct block
 * membership from columns. Like tree-sitter-elm and tree-sitter-roc, this
 * grammar parses declarations/expressions structurally and treats whitespace
 * as insignificant, accepting a superset of what the layout rule admits. That
 * is sound for highlighting: highlighting never gates the compiler's
 * accept/reject or emit (the parity corpus is the drift gate).
 */

const PREC = {
  // Binary operator precedence, loosest to tightest. Mirrors the reference
  // grammar's fixity; only the relative order matters for parse structure.
  or: 2, // ||
  and: 3, // &&
  compare: 4, // == /= < > <= >=
  cons: 5, // ::  (right)
  append: 5, // ++ (right)
  add: 6, // + -
  mul: 7, // * / //
  pipe: 1, // |> <| |= |.
  compose: 9, // >> <<
  application: 10,
  access: 12,
};

module.exports = grammar({
  name: 'ipe',

  extras: ($) => [/\s/, $.line_comment, $.block_comment, $.doc_comment],

  externals: ($) => [$._block_open, $._block_line, $._block_close],

  word: ($) => $.lower_identifier,

  conflicts: ($) => [
    [$._atom, $._pattern_atom],
    [$.constructor_reference, $.constructor_pattern_name],
    [$.value_reference, $.var_pattern],
    [$.unit_expr, $.unit_pattern],
    [$.list_expr, $.list_pattern],
  ],

  rules: {
    source_file: ($) =>
      seq(
        optional(seq($.module_declaration, optional($._block_line))),
        optional(
          seq(
            $._declaration_or_import,
            repeat(seq($._block_line, $._declaration_or_import)),
          ),
        ),
      ),

    _declaration_or_import: ($) => choice($.import, $._declaration),

    // ── Module header ─────────────────────────────────────────────────────
    module_declaration: ($) =>
      seq(
        'module',
        field('name', $.module_name),
        'exposing',
        field('exposing', $.exposing_list),
      ),

    module_name: ($) => $.upper_identifier, // dotted uppers lex as one token

    exposing_list: ($) =>
      seq(
        '(',
        choice(
          $.double_dot,
          commaSep1($.exposed_item),
        ),
        ')',
      ),

    exposed_item: ($) =>
      choice(
        $.lower_identifier,
        seq($.upper_identifier, optional($.exposed_constructors)),
        seq('(', $._operator, ')'),
      ),

    exposed_constructors: ($) =>
      seq('(', choice($.double_dot, commaSep1($.upper_identifier)), ')'),

    // ── Imports ───────────────────────────────────────────────────────────
    import: ($) =>
      seq(
        'import',
        field('module', $.module_name),
        optional(seq('as', field('alias', $.upper_identifier))),
        optional(seq('exposing', field('exposing', $.exposing_list))),
      ),

    // ── Declarations ──────────────────────────────────────────────────────
    _declaration: ($) =>
      choice(
        $.type_declaration,
        $.type_alias_declaration,
        $.foreign_declaration,
        $.type_annotation,
        $.value_declaration,
      ),

    type_declaration: ($) =>
      seq(
        'type',
        field('name', $.upper_identifier),
        repeat(field('parameter', $.lower_identifier)),
        '=',
        $.constructor_list,
      ),

    constructor_list: ($) => sep1('|', $.constructor),

    constructor: ($) =>
      prec.left(seq(field('name', $.upper_identifier), repeat($._type_atom))),

    type_alias_declaration: ($) =>
      seq(
        'type',
        'alias',
        field('name', $.upper_identifier),
        repeat(field('parameter', $.lower_identifier)),
        '=',
        field('body', $._type),
      ),

    foreign_declaration: ($) =>
      seq(
        'foreign',
        field('name', choice($.upper_identifier, $.lower_identifier)),
        '=',
        field('body', $._expression),
      ),

    // `name : Type`. The name is usually lowercase, but a kernel-backed
    // constructor binding annotates an uppercase name too (e.g. `Linear :
    // BackoffStrategy` in Ipe.Task), so both cases are admitted.
    type_annotation: ($) =>
      prec(
        1,
        seq(
          field('name', choice($.lower_identifier, $.upper_identifier)),
          ':',
          field('type', $._type),
        ),
      ),

    // `name p0 p1 = body`. As with the annotation, the bound name may be an
    // uppercase kernel constructor (`Linear = Kernel.kernel "…"`).
    value_declaration: ($) =>
      seq(
        field('name', choice($.lower_identifier, $.upper_identifier)),
        repeat(field('parameter', $._pattern_atom)),
        '=',
        field('body', $._expression),
      ),

    // ── Types ─────────────────────────────────────────────────────────────
    _type: ($) => choice($.arrow_type, $._type_application, $._type_atom),

    arrow_type: ($) =>
      prec.right(seq(choice($._type_application, $._type_atom), '->', $._type)),

    _type_application: ($) =>
      prec.left(1, seq($.type_constructor, repeat1($._type_atom))),

    _type_atom: ($) =>
      choice(
        $.type_constructor,
        $.type_variable,
        $.unit_type,
        $.tuple_type,
        $.record_type,
        seq('(', $._type, ')'),
      ),

    type_constructor: ($) => $.upper_identifier,
    type_variable: ($) => $.lower_identifier,
    unit_type: ($) => seq('(', ')'),

    tuple_type: ($) => seq('(', $._type, repeat1(seq(',', $._type)), ')'),

    record_type: ($) =>
      seq(
        '{',
        optional(seq(field('row_variable', $.lower_identifier), '|')),
        commaSep($.record_type_field),
        '}',
      ),

    record_type_field: ($) =>
      seq(field('field', $.lower_identifier), ':', field('type', $._type)),

    // ── Expressions ───────────────────────────────────────────────────────
    _expression: ($) =>
      choice(
        $.binary_expr,
        $.application,
        $._simple_expression,
        $.lambda,
        $.if_expr,
        $.case_expr,
        $.let_expr,
        $.do_expr,
      ),

    lambda: ($) =>
      prec.right(
        seq('\\', repeat1(field('parameter', $._pattern_atom)), '->', $._expression),
      ),

    if_expr: ($) =>
      prec.right(
        seq(
          'if',
          field('condition', $._expression),
          'then',
          field('consequence', $._expression),
          'else',
          field('alternative', $._expression),
        ),
      ),

    // `case … of` with layout-delimited branches.
    case_expr: ($) =>
      prec.right(
        seq(
          'case',
          field('scrutinee', $._expression),
          'of',
          $._block_open,
          $.case_branch,
          repeat(seq($._block_line, $.case_branch)),
          $._block_close,
        ),
      ),

    case_branch: ($) =>
      seq(field('pattern', $._pattern), '->', field('body', $._expression)),

    // `let … in …`. The binding list is layout-delimited (each binding on its
    // own line); the closing layout token is emitted by the scanner on dedent,
    // and for a same-line terminator by the reduce-point rule in scanner.c.
    let_expr: ($) =>
      seq(
        'let',
        $._block_open,
        $.let_binding,
        repeat(seq($._block_line, $.let_binding)),
        $._block_close,
        'in',
        field('body', $._expression),
      ),

    let_binding: ($) =>
      seq(
        field('name', $._pattern_atom),
        repeat(field('parameter', $._pattern_atom)),
        '=',
        field('value', $._expression),
      ),

    do_expr: ($) =>
      seq(
        'do',
        $._block_open,
        $.do_statement,
        repeat(seq($._block_line, $.do_statement)),
        $._block_close,
      ),

    do_statement: ($) =>
      choice(
        prec(2, seq(field('binder', $._pattern), '<-', field('task', $._expression))),
        prec(1, seq(field('name', $.lower_identifier), '=', field('value', $._expression))),
        $._expression,
      ),

    binary_expr: ($) => {
      const table = [
        ['||', PREC.or, 'right'],
        ['&&', PREC.and, 'right'],
        ['==', PREC.compare, 'left'],
        ['/=', PREC.compare, 'left'],
        ['<', PREC.compare, 'left'],
        ['>', PREC.compare, 'left'],
        ['<=', PREC.compare, 'left'],
        ['>=', PREC.compare, 'left'],
        ['::', PREC.cons, 'right'],
        ['++', PREC.append, 'right'],
        ['+', PREC.add, 'left'],
        ['-', PREC.add, 'left'],
        ['*', PREC.mul, 'left'],
        ['/', PREC.mul, 'left'],
        ['//', PREC.mul, 'left'],
        ['|>', PREC.pipe, 'left'],
        ['<|', PREC.pipe, 'right'],
        ['|=', PREC.pipe, 'left'],
        ['|.', PREC.pipe, 'left'],
        ['>>', PREC.compose, 'right'],
        ['<<', PREC.compose, 'right'],
      ];
      return choice(
        ...table.map(([op, p, assoc]) => {
          const rule = seq(
            field('left', $._expression),
            field('operator', alias(op, $.operator)),
            field('right', $._expression),
          );
          return assoc === 'left' ? prec.left(p, rule) : prec.right(p, rule);
        }),
      );
    },

    application: ($) =>
      prec.left(
        PREC.application,
        seq(
          field('function', $._simple_expression),
          repeat1(field('argument', $._simple_expression)),
        ),
      ),

    _simple_expression: ($) =>
      choice(
        $.field_access,
        $._atom,
      ),

    field_access: ($) =>
      prec.left(
        PREC.access,
        seq($._atom, repeat1(seq('.', field('field', $.lower_identifier)))),
      ),

    // Prefix negation `-e` (`-5`, `-x`, `-(e)`). Only in atom (fresh-operand)
    // position; `a - b` is binary subtraction (parser.rs parse_negative_literal
    // vs peek_binop). The operand is adjacent in the compiler; for highlighting
    // the exact adjacency is not enforced.
    negation: ($) => prec(PREC.application + 1, seq('-', $._simple_expression)),

    _atom: ($) =>
      choice(
        $.negation,
        $.value_qualified,
        $.value_reference,
        $.constructor_reference,
        $.number_literal,
        $.string_literal,
        $.triple_string_literal,
        $.char_literal,
        $.unit_expr,
        $.list_expr,
        $.tuple_expr,
        $.record_expr,
        $.record_update,
        $.parenthesized_expr,
      ),

    value_qualified: ($) => $.qualified_lower, // Qualifier.name (dotted, ends lower)
    value_reference: ($) => $.lower_identifier,
    constructor_reference: ($) => $.upper_identifier,

    unit_expr: ($) => seq('(', ')'),
    parenthesized_expr: ($) => seq('(', $._expression, ')'),
    tuple_expr: ($) =>
      seq('(', $._expression, repeat1(seq(',', $._expression)), ')'),

    list_expr: ($) => seq('[', commaSep($._expression), ']'),

    record_expr: ($) => seq('{', commaSep($.record_field), '}'),

    record_field: ($) =>
      seq(field('name', $.lower_identifier), '=', field('value', $._expression)),

    // `{ base | field = value, ... }`
    record_update: ($) =>
      seq(
        '{',
        field('base', $.lower_identifier),
        '|',
        commaSep1($.record_field),
        '}',
      ),

    // ── Patterns ──────────────────────────────────────────────────────────
    _pattern: ($) => choice($.cons_pattern, $.or_pattern, $.as_pattern, $._pattern_app),

    cons_pattern: ($) =>
      prec.right(seq($._pattern_app, '::', $._pattern)),

    or_pattern: ($) =>
      prec.left(seq($._pattern_app, repeat1(seq('|', $._pattern_app)))),

    as_pattern: ($) =>
      prec.left(seq($._pattern_app, 'as', field('alias', $.lower_identifier))),

    _pattern_app: ($) =>
      choice(
        prec.left(seq($.constructor_pattern_name, repeat1($._pattern_atom))),
        $._pattern_atom,
      ),

    constructor_pattern_name: ($) => choice($.upper_identifier, $.qualified_upper),

    _pattern_atom: ($) =>
      choice(
        $.wildcard_pattern,
        $.var_pattern,
        $.constructor_pattern_name,
        $.number_literal,
        $.string_literal,
        $.char_literal,
        $.bool_pattern,
        $.unit_pattern,
        $.list_pattern,
        $.tuple_pattern,
        $.record_pattern,
        seq('(', $._pattern, ')'),
      ),

    wildcard_pattern: ($) => '_',
    var_pattern: ($) => $.lower_identifier,
    bool_pattern: ($) => choice('True', 'False'),
    unit_pattern: ($) => seq('(', ')'),
    list_pattern: ($) => seq('[', commaSep($._pattern), ']'),
    tuple_pattern: ($) =>
      seq('(', $._pattern, repeat1(seq(',', $._pattern)), ')'),
    record_pattern: ($) => seq('{', commaSep1($.lower_identifier), '}'),

    // ── Operators (as a set, for the `(op)` exposed form) ─────────────────
    _operator: ($) =>
      choice(
        '||', '&&', '==', '/=', '<', '>', '<=', '>=', '::', '++',
        '+', '-', '*', '/', '//', '|>', '<|', '|=', '|.', '>>', '<<',
      ),

    // ── Literals & lexical tokens ─────────────────────────────────────────
    // Numbers: integer or Elm-style float (lexer.rs lex_number). A leading
    // digit is required (`.5` is not a float).
    number_literal: ($) =>
      token(
        choice(
          /\d+\.\d+([eE][+-]?\d+)?/, // float with fraction
          /\d+[eE][+-]?\d+/, // float with exponent only
          /\d+/, // integer
        ),
      ),

    string_literal: ($) =>
      seq(
        '"',
        repeat(choice($.escape_sequence, token.immediate(prec(1, /[^"\\\n]+/)))),
        '"',
      ),

    // Triple-quoted string. Content is raw; the closing terminator is exactly
    // three quotes (lexer.rs lex_triple_string). Interpolation `{{expr}}` is
    // raw content here (resolved downstream by the canonicaliser).
    triple_string_literal: ($) =>
      seq('"""', repeat(choice($.interpolation, $._triple_string_content)), '"""'),

    _triple_string_content: ($) =>
      token.immediate(prec(1, /([^"{\\]|"[^"]|""[^"]|\\.|\{[^{])+/)),

    interpolation: ($) => seq('{{', /[^}]*/, '}}'),

    char_literal: ($) =>
      seq("'", choice($.escape_sequence, token.immediate(/[^'\\\n]/)), "'"),

    escape_sequence: ($) =>
      token.immediate(seq('\\', choice('n', 't', 'r', '\\', '"', "'", '0'))),

    // ── Comments ──────────────────────────────────────────────────────────
    line_comment: ($) => token(seq('--', /[^\n]*/)),

    // `{-| … -}` doc comment — captured separately for highlighting.
    doc_comment: ($) => token(seq('{-|', /([^-]|-[^}])*/, '-}')),

    // `{- … -}` nestable block comment. Handled by an external-free token via a
    // regex that allows a single level; deeper nesting is covered by the
    // greedy alternation. tree-sitter cannot express unbounded nesting in a
    // single token regex, so this admits the common one/two-level forms the
    // corpus uses; the parity gate confirms no ERROR over the real corpus.
    block_comment: ($) =>
      token(
        seq(
          '{-',
          /[^|]/, // a doc comment `{-|` is a distinct token
          repeat(choice(/[^-{]/, /-[^}]/, /\{[^-]/)),
          repeat('-'),
          '}',
        ),
      ),

    // ── Identifiers ───────────────────────────────────────────────────────
    // A lowercase identifier: starts with a lowercase letter or underscore.
    // (`_foo` binder names such as `_req` occur in the corpus.)
    lower_identifier: ($) => /[a-z_][A-Za-z0-9_]*/,

    // An uppercase (possibly dotted) name: `Msg`, `String`, `Ipe.Tea.Web`.
    // The lexer lexes a dotted run ending in an Upper segment as one token.
    upper_identifier: ($) => /[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*/,

    // `Qualifier.name` — dotted, final segment lowercase (`String.fromInt`).
    qualified_lower: ($) =>
      token(/[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*\.[a-z][A-Za-z0-9_]*/),

    // `Qualifier.Ctor` used as a constructor pattern head.
    qualified_upper: ($) =>
      token(/[A-Z][A-Za-z0-9_]*\.[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*/),

    double_dot: ($) => '..',
  },
});

function commaSep(rule) {
  return optional(commaSep1(rule));
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(',', rule)));
}

function sep1(separator, rule) {
  return seq(rule, repeat(seq(separator, rule)));
}
