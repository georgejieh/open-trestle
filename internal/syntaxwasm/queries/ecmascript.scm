; Patterns shared by the JavaScript, TypeScript and TSX packs. They use only
; node types and fields the three grammars have in common.

; Functions and methods.
(function_declaration name: (identifier) @name) @definition.function
(generator_function_declaration name: (identifier) @name) @definition.function
(function_expression name: (identifier) @name) @definition.function
(variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression) (generator_function)]) @definition.function
(pair key: [(property_identifier) (string)] @name value: [(arrow_function) (function_expression) (generator_function)]) @definition.function
(assignment_expression left: (member_expression property: (property_identifier) @name) right: [(arrow_function) (function_expression) (generator_function)]) @definition.function
(method_definition name: [(property_identifier) (private_property_identifier)] @name) @definition.method

; Module-level bindings. Locals are not definitions.
(program (lexical_declaration "const" (variable_declarator name: (identifier) @name) @definition.constant))
(program (lexical_declaration "let" (variable_declarator name: (identifier) @name) @definition.variable))
(program (variable_declaration (variable_declarator name: (identifier) @name) @definition.variable))
(program (export_statement declaration: (lexical_declaration "const" (variable_declarator name: (identifier) @name @exported) @definition.constant)))
(program (export_statement declaration: (lexical_declaration "let" (variable_declarator name: (identifier) @name @exported) @definition.variable)))
(program (export_statement declaration: (variable_declaration (variable_declarator name: (identifier) @name @exported) @definition.variable)))

; Exported declarations and export lists.
(export_statement declaration: (function_declaration name: (identifier) @name @exported) @definition.function)
(export_statement declaration: (generator_function_declaration name: (identifier) @name @exported) @definition.function)
(export_statement declaration: (lexical_declaration (variable_declarator name: (identifier) @name @exported value: [(arrow_function) (function_expression)]) @definition.function))
(export_statement !source (export_clause (export_specifier name: (identifier) @name))) @export
(export_statement value: (identifier) @name) @export

; Calls, constructions and decorators.
(call_expression function: (identifier) @name) @reference.call
(call_expression function: (member_expression object: [(identifier) (this) (super) (member_expression)] @qualifier property: [(property_identifier) (private_property_identifier)] @name)) @reference.call
(call_expression function: (member_expression object: [(call_expression) (new_expression) (parenthesized_expression) (subscript_expression) (string) (template_string) (array) (await_expression)] property: [(property_identifier) (private_property_identifier)] @name)) @reference.call
(new_expression constructor: (identifier) @name) @reference.construct
(new_expression constructor: (member_expression object: [(identifier) (this) (member_expression)] @qualifier property: (property_identifier) @name)) @reference.construct
(decorator (identifier) @name) @reference.decorator
(decorator (member_expression property: (property_identifier) @name)) @reference.decorator
(decorator (call_expression function: (identifier) @name)) @reference.decorator
(decorator (call_expression function: (member_expression property: (property_identifier) @name))) @reference.decorator

; Imports: static, re-exports, dynamic import() and require().
(import_statement source: (string (string_fragment) @import.source)) @import
(import_statement (import_clause (identifier) @import.alias) source: (string (string_fragment) @import.source)) @import
(import_statement (import_clause (namespace_import (identifier) @import.alias)) source: (string (string_fragment) @import.source)) @import
(import_statement (import_clause (named_imports (import_specifier !alias name: (_) @import.name))) source: (string (string_fragment) @import.source)) @import
(import_statement (import_clause (named_imports (import_specifier name: (_) @import.name alias: (identifier) @import.alias))) source: (string (string_fragment) @import.source)) @import
(export_statement source: (string (string_fragment) @import.source)) @import
(call_expression function: (import) arguments: (arguments . (string (string_fragment) @import.source))) @import
(call_expression function: (identifier) @match.require arguments: (arguments . (string (string_fragment) @import.source) .)) @import
(export_statement (export_clause (export_specifier !alias name: (_) @import.name)) source: (string (string_fragment) @import.source)) @import
(export_statement (export_clause (export_specifier name: (_) @import.name alias: (_) @import.alias)) source: (string (string_fragment) @import.source)) @import

; A class expression bound to a name is a class definition.
(variable_declarator name: (identifier) @name value: (class)) @definition.class
