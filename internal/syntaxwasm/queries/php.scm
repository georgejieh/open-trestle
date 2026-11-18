; PHP query pack. Capture vocabulary: docs/syntax-analysis.md.

; Namespaces and types. A trait is recorded as a class. Visibility is
; applied by finishPHP, because a member without a modifier is public.
(namespace_definition name: (namespace_name) @name) @definition.module
(class_declaration name: (name) @name) @definition.class
(interface_declaration name: (name) @name) @definition.interface
(trait_declaration name: (name) @name) @definition.class
(enum_declaration name: (name) @name) @definition.enum

; Functions, methods, constants, properties and enum cases. A constructor
; parameter that declares a property is a field; finishPHP moves it from
; the constructor to the class.
(function_definition name: (name) @name) @definition.function
(method_declaration name: (name) @name) @definition.method
(enum_case name: (name) @name) @definition.constant
(const_declaration (const_element . (name) @name)) @definition.constant
(property_declaration (property_element name: (variable_name (name) @name))) @definition.field
(property_promotion_parameter name: [(variable_name (name) @name) (by_ref (variable_name (name) @name))]) @definition.field
(function_call_expression function: (name) @match.define arguments: (arguments . (argument (string (string_content) @name)))) @definition.constant

; Variables assigned at file level are globals.
(program (expression_statement (assignment_expression left: (variable_name (name) @name)) @definition.variable))

; Calls.
(function_call_expression function: (name) @name) @reference.call
(function_call_expression function: (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.call
(member_call_expression object: [(variable_name) (member_access_expression) (nullsafe_member_access_expression)] @qualifier name: (name) @name) @reference.call
(member_call_expression name: (name) @name) @reference.call
(nullsafe_member_call_expression object: [(variable_name) (member_access_expression) (nullsafe_member_access_expression)] @qualifier name: (name) @name) @reference.call
(nullsafe_member_call_expression name: (name) @name) @reference.call
(scoped_call_expression scope: [(name) (qualified_name) (relative_scope)] @qualifier name: (name) @name) @reference.call
(scoped_call_expression name: (name) @name) @reference.call

; Constructions.
(object_creation_expression (name) @name) @reference.construct
(object_creation_expression (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.construct

; Types, inheritance, trait use and attributes.
(named_type (name) @name) @reference.type
(named_type (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.type
(binary_expression operator: "instanceof" right: (name) @name) @reference.type
(binary_expression operator: "instanceof" right: (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.type
(base_clause (name) @name) @reference.inherit
(base_clause (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.inherit
(class_interface_clause (name) @name) @reference.inherit
(class_interface_clause (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.inherit
(use_declaration (name) @name) @reference.inherit
(use_declaration (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.inherit
(attribute (name) @name) @reference.decorator
(attribute (qualified_name prefix: (namespace_name)? @qualifier (name) @name)) @reference.decorator

; Namespace imports. A group import has the shared prefix as its source and
; each member as a name.
(namespace_use_declaration (namespace_use_clause . [(qualified_name) (name)] @import.source) @import)
(namespace_use_declaration (namespace_use_clause . [(qualified_name) (name)] @import.source alias: (name) @import.alias) @import)
(namespace_use_declaration (namespace_name) @import.source body: (namespace_use_group (namespace_use_clause . [(qualified_name) (name)] @import.name) @import))
(namespace_use_declaration (namespace_name) @import.source body: (namespace_use_group (namespace_use_clause . [(qualified_name) (name)] @import.name alias: (name) @import.alias) @import))

; File inclusion with a literal path, alone or after __DIR__.
(include_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)]) @import
(include_once_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)]) @import
(require_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)]) @import
(require_once_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)]) @import
(include_expression (parenthesized_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)])) @import
(include_once_expression (parenthesized_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)])) @import
(require_expression (parenthesized_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)])) @import
(require_once_expression (parenthesized_expression [(string (string_content) @import.source) (encapsed_string . (string_content) @import.source .)])) @import
(include_expression (binary_expression left: (name) @match.__DIR__ right: (string (string_content) @import.source))) @import
(include_once_expression (binary_expression left: (name) @match.__DIR__ right: (string (string_content) @import.source))) @import
(require_expression (binary_expression left: (name) @match.__DIR__ right: (string (string_content) @import.source))) @import
(require_once_expression (binary_expression left: (name) @match.__DIR__ right: (string (string_content) @import.source))) @import
(namespace_definition body: (compound_statement (expression_statement (assignment_expression left: (variable_name (name) @name)) @definition.variable)))
