; Python query pack. Capture vocabulary: docs/syntax-analysis.md.

; Functions and classes, with their decorators when decorated.
(function_definition name: (identifier) @name) @definition.function
(decorated_definition definition: (function_definition name: (identifier) @name)) @definition.function
(class_definition name: (identifier) @name) @definition.class
(decorated_definition definition: (class_definition name: (identifier) @name)) @definition.class

; Module and class level bindings. Locals are not definitions.
(module (expression_statement (assignment left: (identifier) @name) @definition.variable))
(module (expression_statement (assignment left: (pattern_list (identifier) @name @definition.variable))))
(class_definition body: (block (expression_statement (assignment left: (identifier) @name) @definition.field)))
(module (type_alias_statement left: (type (identifier) @name)) @definition.type)

; __all__ lists the module's exported names.
(module (expression_statement (assignment left: (identifier) @match.__all__ right: [(list (string (string_content) @name)) (tuple (string (string_content) @name))])) @export)

; Calls and decorators.
(call function: (identifier) @name) @reference.call
(call function: (attribute object: [(identifier) (attribute)] @qualifier attribute: (identifier) @name)) @reference.call
(call function: (attribute object: [(call) (subscript) (string) (parenthesized_expression) (list) (dictionary)] attribute: (identifier) @name)) @reference.call
(decorator (identifier) @name) @reference.decorator
(decorator (attribute object: [(identifier) (attribute)] @qualifier attribute: (identifier) @name)) @reference.decorator
(decorator (call function: (identifier) @name)) @reference.decorator
(decorator (call function: (attribute object: [(identifier) (attribute)] @qualifier attribute: (identifier) @name))) @reference.decorator

; Base classes and annotations.
(class_definition superclasses: (argument_list (identifier) @name)) @reference.inherit
(class_definition superclasses: (argument_list (attribute object: [(identifier) (attribute)] @qualifier attribute: (identifier) @name))) @reference.inherit
(class_definition superclasses: (argument_list (subscript value: (identifier) @name))) @reference.inherit
(type (identifier) @name) @reference.type
(type (attribute object: [(identifier) (attribute)] @qualifier attribute: (identifier) @name)) @reference.type
(type (generic_type (identifier) @name)) @reference.type
(type (subscript value: (identifier) @name)) @reference.type

; Imports.
(import_statement name: (dotted_name) @import.source) @import
(import_statement name: (aliased_import name: (dotted_name) @import.source alias: (identifier) @import.alias)) @import
(import_from_statement module_name: (_) @import.source name: (dotted_name) @import.name) @import
(import_from_statement module_name: (_) @import.source name: (aliased_import name: (dotted_name) @import.name alias: (identifier) @import.alias)) @import
(import_from_statement module_name: (_) @import.source (wildcard_import) @import.name) @import
(future_import_statement "__future__" @import.source name: (dotted_name) @import.name) @import
(future_import_statement "__future__" @import.source name: (aliased_import name: (dotted_name) @import.name alias: (identifier) @import.alias)) @import
