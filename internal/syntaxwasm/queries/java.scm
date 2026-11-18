; Java query pack. Capture vocabulary: docs/syntax-analysis.md.

; Package and type definitions.
(package_declaration [(identifier) (scoped_identifier)] @name) @definition.module

(class_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.class
(record_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.class
(interface_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.interface
(annotation_type_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.interface
(enum_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.enum

; Members.
(method_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.method
(constructor_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.constructor
(compact_constructor_declaration (modifiers "public" @exported)? name: (identifier) @name) @definition.constructor
(annotation_type_element_declaration name: (identifier) @name) @definition.method
(field_declaration (modifiers "public" @exported)? declarator: (variable_declarator name: (identifier) @name) @definition.field)
(field_declaration (modifiers "static" "final") declarator: (variable_declarator name: (identifier) @name) @definition.constant)
(field_declaration (modifiers "final" "static") declarator: (variable_declarator name: (identifier) @name) @definition.constant)
(constant_declaration declarator: (variable_declarator name: (identifier) @name) @definition.constant)
(enum_constant name: (identifier) @name) @definition.constant

; Calls and constructions.
(method_invocation object: [(identifier) (field_access) (this) (super)] @qualifier name: (identifier) @name) @reference.call
(method_invocation !object name: (identifier) @name) @reference.call
(method_invocation object: [(method_invocation) (object_creation_expression) (parenthesized_expression) (array_access) (class_literal) (string_literal)] name: (identifier) @name) @reference.call
(method_reference (identifier) @name .) @reference.call
(object_creation_expression type: (type_identifier) @name) @reference.construct
(object_creation_expression type: (generic_type (type_identifier) @name)) @reference.construct
(object_creation_expression type: (scoped_type_identifier (type_identifier) @name .)) @reference.construct
(object_creation_expression type: (generic_type (scoped_type_identifier (type_identifier) @name .))) @reference.construct

; Types, inheritance and annotations.
(type_identifier) @name @reference.type
(superclass [(type_identifier) @name (generic_type (type_identifier) @name) (scoped_type_identifier (type_identifier) @name .)]) @reference.inherit
(super_interfaces (type_list [(type_identifier) @name (generic_type (type_identifier) @name) (scoped_type_identifier (type_identifier) @name .)])) @reference.inherit
(extends_interfaces (type_list [(type_identifier) @name (generic_type (type_identifier) @name) (scoped_type_identifier (type_identifier) @name .)])) @reference.inherit
(marker_annotation name: (identifier) @name) @reference.decorator
(marker_annotation name: (scoped_identifier name: (identifier) @name)) @reference.decorator
(annotation name: (identifier) @name) @reference.decorator
(annotation name: (scoped_identifier name: (identifier) @name)) @reference.decorator

; Imports. A wildcard import keeps the asterisk as its member name.
(import_declaration [(identifier) (scoped_identifier)] @import.source) @import
(import_declaration [(identifier) (scoped_identifier)] @import.source (asterisk) @import.name) @import
