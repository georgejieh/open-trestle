; TypeScript and TSX patterns; ecmascript.scm holds the ones shared with
; JavaScript. TSX adds the JSX patterns in jsx.scm.

; Types and classes.
(class_declaration name: (type_identifier) @name) @definition.class
(class name: (type_identifier) @name) @definition.class
(abstract_class_declaration name: (type_identifier) @name) @definition.class
(interface_declaration name: (type_identifier) @name) @definition.interface
(type_alias_declaration name: (type_identifier) @name) @definition.type
(enum_declaration name: (identifier) @name) @definition.enum
(internal_module name: [(identifier) (nested_identifier)] @name) @definition.module
(module name: [(identifier) (nested_identifier)] @name) @definition.module

; Exported declarations.
(export_statement declaration: (class_declaration name: (type_identifier) @name @exported) @definition.class)
(export_statement declaration: (abstract_class_declaration name: (type_identifier) @name @exported) @definition.class)
(export_statement declaration: (interface_declaration name: (type_identifier) @name @exported) @definition.interface)
(export_statement declaration: (type_alias_declaration name: (type_identifier) @name @exported) @definition.type)
(export_statement declaration: (enum_declaration name: (identifier) @name @exported) @definition.enum)
(export_statement declaration: (internal_module name: [(identifier) (nested_identifier)] @name @exported) @definition.module)
(export_statement declaration: (function_signature name: (identifier) @name @exported) @definition.function)
(export_statement declaration: (ambient_declaration (function_signature name: (identifier) @name @exported) @definition.function))

; Members and signatures.
(function_signature name: (identifier) @name) @definition.function
(method_signature name: [(property_identifier) (private_property_identifier)] @name) @definition.method
(abstract_method_signature name: [(property_identifier) (private_property_identifier)] @name) @definition.method
(property_signature name: [(property_identifier) (private_property_identifier)] @name) @definition.field
(public_field_definition name: [(property_identifier) (private_property_identifier)] @name) @definition.field
(enum_body name: (property_identifier) @name @definition.constant)
(enum_assignment name: (property_identifier) @name) @definition.constant

; Type uses and inheritance.
(type_identifier) @name @reference.type
(nested_type_identifier module: [(identifier) (nested_identifier)] @qualifier name: (type_identifier) @name) @reference.type
(extends_clause value: (identifier) @name) @reference.inherit
(extends_clause value: (member_expression object: [(identifier) (member_expression)] @qualifier property: (property_identifier) @name)) @reference.inherit
(implements_clause [(type_identifier) @name (generic_type name: (type_identifier) @name) (nested_type_identifier name: (type_identifier) @name)]) @reference.inherit
(extends_type_clause type: [(type_identifier) @name (generic_type name: (type_identifier) @name) (nested_type_identifier name: (type_identifier) @name)]) @reference.inherit

; import x = require("y") and import x = A.B.
(import_statement (import_require_clause (identifier) @import.alias source: (string (string_fragment) @import.source))) @import
(import_alias (identifier) @import.alias [(identifier) (nested_identifier)] @import.source) @import
