; C# query pack. Capture vocabulary: docs/syntax-analysis.md.
;
; A member is exported when it carries the `public` modifier. Each pattern
; that can be exported comes twice: once for the definition and once with
; the modifier. The two records describe one definition and are merged.
; Members of an interface and of an enum take the visibility of their owner.

; Namespaces. A file-scoped namespace covers the rest of the file; the
; finishing step extends it.
(namespace_declaration name: (_) @name) @definition.module
(file_scoped_namespace_declaration name: (_) @name) @definition.module

; Types. A record is a class here; the finishing step makes a record struct a
; struct.
(class_declaration name: (identifier) @name) @definition.class
(class_declaration (modifier "public") @exported name: (identifier) @name) @definition.class
(struct_declaration name: (identifier) @name) @definition.struct
(struct_declaration (modifier "public") @exported name: (identifier) @name) @definition.struct
(record_declaration name: (identifier) @name) @definition.class
(record_declaration (modifier "public") @exported name: (identifier) @name) @definition.class
(interface_declaration name: (identifier) @name) @definition.interface
(interface_declaration (modifier "public") @exported name: (identifier) @name) @definition.interface
(enum_declaration name: (identifier) @name) @definition.enum
(enum_declaration (modifier "public") @exported name: (identifier) @name) @definition.enum
(enum_member_declaration name: (identifier) @name) @definition.constant
(delegate_declaration name: (identifier) @name) @definition.type
(delegate_declaration (modifier "public") @exported name: (identifier) @name) @definition.type

; Methods, constructors, operators and local functions.
(method_declaration name: (identifier) @name) @definition.method
(method_declaration (modifier "public") @exported name: (identifier) @name) @definition.method
(constructor_declaration name: (identifier) @name) @definition.constructor
(constructor_declaration (modifier "public") @exported name: (identifier) @name) @definition.constructor
(destructor_declaration name: (identifier) @name) @definition.method
(operator_declaration operator: _ @name) @definition.method
(operator_declaration (modifier "public") @exported operator: _ @name) @definition.method
(conversion_operator_declaration type: (_) @name) @definition.method
(conversion_operator_declaration (modifier "public") @exported type: (_) @name) @definition.method
(local_function_statement name: (identifier) @name) @definition.function

; Properties, indexers, events and fields. A positional record parameter is
; a property, exported with a public record.
(property_declaration name: (identifier) @name) @definition.field
(property_declaration (modifier "public") @exported name: (identifier) @name) @definition.field
(indexer_declaration "this" @name) @definition.field
(indexer_declaration (modifier "public") @exported "this" @name) @definition.field
(event_declaration name: (identifier) @name) @definition.field
(event_declaration (modifier "public") @exported name: (identifier) @name) @definition.field
(event_field_declaration (variable_declaration (variable_declarator name: (identifier) @name) @definition.field))
(event_field_declaration (modifier "public") @exported (variable_declaration (variable_declarator name: (identifier) @name) @definition.field))
(field_declaration (variable_declaration (variable_declarator name: (identifier) @name) @definition.field))
(field_declaration (modifier "public") @exported (variable_declaration (variable_declarator name: (identifier) @name) @definition.field))
(field_declaration (modifier "const") (variable_declaration (variable_declarator name: (identifier) @name) @definition.constant))
(field_declaration (modifier "static") (modifier "readonly") (variable_declaration (variable_declarator name: (identifier) @name) @definition.constant))
(field_declaration (modifier "readonly") (modifier "static") (variable_declaration (variable_declarator name: (identifier) @name) @definition.constant))
(record_declaration (parameter_list (parameter name: (identifier) @name) @definition.field))
(record_declaration (modifier "public") @exported (parameter_list (parameter name: (identifier) @name) @definition.field))

; Calls and constructions.
(invocation_expression function: (identifier) @name) @reference.call
(invocation_expression function: (generic_name . (identifier) @name)) @reference.call
(invocation_expression function: (member_access_expression name: (identifier) @name)) @reference.call
(invocation_expression function: (member_access_expression name: (generic_name . (identifier) @name))) @reference.call
(invocation_expression function: (member_access_expression expression: [(identifier) "this" "base" (member_access_expression)] @qualifier name: (identifier) @name)) @reference.call
(invocation_expression function: (member_access_expression expression: [(identifier) "this" "base" (member_access_expression)] @qualifier name: (generic_name . (identifier) @name))) @reference.call
(invocation_expression function: (conditional_access_expression (member_binding_expression name: (identifier) @name))) @reference.call
(invocation_expression function: (conditional_access_expression condition: [(identifier) "this" "base" (member_access_expression)] @qualifier (member_binding_expression name: (identifier) @name))) @reference.call
(object_creation_expression type: (identifier) @name) @reference.construct
(object_creation_expression type: (generic_name . (identifier) @name)) @reference.construct
(object_creation_expression type: (qualified_name name: (identifier) @name)) @reference.construct
(object_creation_expression type: (qualified_name name: (generic_name . (identifier) @name))) @reference.construct
(object_creation_expression type: (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name)) @reference.construct

; Types: every type position and the generic arguments. A name written with a qualifier keeps it.
(_ type: (identifier) @name @reference.type)
(_ returns: (identifier) @name @reference.type)
(_ type: (qualified_name name: (identifier) @name) @reference.type)
(_ returns: (qualified_name name: (identifier) @name) @reference.type)
(_ type: (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name) @reference.type)
(_ returns: (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name) @reference.type)
(_ type: (generic_name . (identifier) @name @reference.type))
(_ returns: (generic_name . (identifier) @name @reference.type))
(_ type: (qualified_name name: (generic_name . (identifier) @name @reference.type)))
(type_argument_list (generic_name . (identifier) @name @reference.type))
(explicit_interface_specifier [(identifier) @name @reference.type (generic_name . (identifier) @name @reference.type)])
(type_argument_list (identifier) @name @reference.type)
(type_argument_list (qualified_name name: (identifier) @name) @reference.type)
(type_argument_list (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name) @reference.type)

; Base types and attributes.
(base_list [(identifier) @name (generic_name . (identifier) @name) (qualified_name name: (identifier) @name) (qualified_name name: (generic_name . (identifier) @name))]) @reference.inherit
(base_list (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name)) @reference.inherit
(primary_constructor_base_type type: [(identifier) @name (generic_name . (identifier) @name) (qualified_name name: (identifier) @name)]) @reference.inherit
(attribute name: (identifier) @name) @reference.decorator
(attribute name: (qualified_name name: (identifier) @name)) @reference.decorator
(attribute name: (qualified_name qualifier: [(identifier) (qualified_name)] @qualifier name: (identifier) @name)) @reference.decorator

; Imports. A using directive names a namespace or a type; an alias is kept
; as the alias of the type it stands for.
(using_directive !name [(identifier) (qualified_name) (alias_qualified_name)] @import.source) @import
(using_directive name: (identifier) @import.alias . (_) @import.source) @import
