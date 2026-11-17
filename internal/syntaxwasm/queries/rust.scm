; Rust query pack. Capture vocabulary: docs/syntax-analysis.md.
;
; An item is exported when it is declared with a bare `pub`. Each pattern
; that can be exported comes twice: once for the definition and once with
; the visibility marker, whose match is kept only for the text `pub`. The
; two records describe one definition and are merged.

; Functions and members. A function inside an impl or a trait becomes a
; method.
(function_item name: (identifier) @name) @definition.function
(function_item (visibility_modifier) @match.pub @exported name: (identifier) @name) @definition.function
(function_signature_item name: (identifier) @name) @definition.function
(function_signature_item (visibility_modifier) @match.pub @exported name: (identifier) @name) @definition.function

; Types. An impl block is a class named after the implemented type, so
; that its functions are its methods and its members are qualified by the
; type. An impl of a trait is exported: the trait decides who can call it.
[(struct_item name: (type_identifier) @name) (union_item name: (type_identifier) @name)] @definition.struct
[(struct_item (visibility_modifier) @match.pub @exported name: (type_identifier) @name) (union_item (visibility_modifier) @match.pub @exported name: (type_identifier) @name)] @definition.struct
(enum_item name: (type_identifier) @name) @definition.enum
(enum_item (visibility_modifier) @match.pub @exported name: (type_identifier) @name) @definition.enum
(enum_variant name: (identifier) @name) @definition.constant
(trait_item name: (type_identifier) @name) @definition.interface
(trait_item (visibility_modifier) @match.pub @exported name: (type_identifier) @name) @definition.interface
(type_item name: (type_identifier) @name) @definition.type
(type_item (visibility_modifier) @match.pub @exported name: (type_identifier) @name) @definition.type
(associated_type name: (type_identifier) @name) @definition.type

(impl_item type: [
  (type_identifier) @name
  (primitive_type) @name
  (generic_type type: (type_identifier) @name)
  (generic_type type: (scoped_type_identifier name: (type_identifier) @name))
  (scoped_type_identifier name: (type_identifier) @name)
  (reference_type type: (type_identifier) @name)
  (reference_type type: (generic_type type: (type_identifier) @name))
]) @definition.class
(impl_item trait: (_) @exported type: [
  (type_identifier) @name
  (primitive_type) @name
  (generic_type type: (type_identifier) @name)
  (generic_type type: (scoped_type_identifier name: (type_identifier) @name))
  (scoped_type_identifier name: (type_identifier) @name)
  (reference_type type: (type_identifier) @name)
  (reference_type type: (generic_type type: (type_identifier) @name))
]) @definition.class

; Modules, constants, statics and macros.
(mod_item name: (identifier) @name) @definition.module
(mod_item (visibility_modifier) @match.pub @exported name: (identifier) @name) @definition.module
(const_item name: (identifier) @name) @definition.constant
(const_item (visibility_modifier) @match.pub @exported name: (identifier) @name) @definition.constant
(static_item name: (identifier) @name) @definition.variable
(static_item (visibility_modifier) @match.pub @exported name: (identifier) @name) @definition.variable
(macro_definition name: (identifier) @name) @definition.macro

; Named fields of structs and unions.
(struct_item body: (field_declaration_list (field_declaration name: (field_identifier) @name) @definition.field))
(struct_item body: (field_declaration_list (field_declaration (visibility_modifier) @match.pub @exported name: (field_identifier) @name) @definition.field))
(union_item body: (field_declaration_list (field_declaration name: (field_identifier) @name) @definition.field))
(union_item body: (field_declaration_list (field_declaration (visibility_modifier) @match.pub @exported name: (field_identifier) @name) @definition.field))

; Calls. A macro invocation is recorded as a call of the macro. The
; arguments of a macro are not parsed, so calls written inside them are not
; seen.
(call_expression function: (identifier) @name) @reference.call
(call_expression function: (scoped_identifier name: (identifier) @name)) @reference.call
(call_expression function: (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (identifier) @name)) @reference.call
(call_expression function: (field_expression field: (field_identifier) @name)) @reference.call
(call_expression function: (field_expression value: [(identifier) (self) (field_expression)] @qualifier field: (field_identifier) @name)) @reference.call
(call_expression function: (generic_function function: (identifier) @name)) @reference.call
(call_expression function: (generic_function function: (scoped_identifier name: (identifier) @name))) @reference.call
(call_expression function: (generic_function function: (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (identifier) @name))) @reference.call
(call_expression function: (generic_function function: (field_expression field: (field_identifier) @name))) @reference.call
(call_expression function: (generic_function function: (field_expression value: [(identifier) (self) (field_expression)] @qualifier field: (field_identifier) @name))) @reference.call
(macro_invocation macro: (identifier) @name) @reference.call
(macro_invocation macro: (scoped_identifier name: (identifier) @name)) @reference.call
(macro_invocation macro: (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (identifier) @name)) @reference.call

; Struct literals construct their type.
(struct_expression name: [(type_identifier) @name (generic_type type: (type_identifier) @name) (scoped_type_identifier name: (type_identifier) @name)]) @reference.construct
(struct_expression name: (scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name)) @reference.construct

; Types, supertraits, implemented traits and attributes.
(type_identifier) @name @reference.type
(scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name) @reference.type
(impl_item trait: [(type_identifier) @name (generic_type type: (type_identifier) @name) (scoped_type_identifier name: (type_identifier) @name)]) @reference.inherit
(impl_item trait: [(scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name) (generic_type type: (scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name))]) @reference.inherit
(trait_item bounds: (trait_bounds [(type_identifier) @name (generic_type type: (type_identifier) @name) (scoped_type_identifier name: (type_identifier) @name)])) @reference.inherit
(trait_item bounds: (trait_bounds [(scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name) (generic_type type: (scoped_type_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (type_identifier) @name))])) @reference.inherit
(attribute . (identifier) @name) @reference.decorator
(attribute . (scoped_identifier name: (identifier) @name)) @reference.decorator
(attribute . (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @qualifier name: (identifier) @name)) @reference.decorator

; A derive lists the traits it implements, as plain names.
(attribute . (identifier) @match.derive arguments: (token_tree "(" . (identifier) @name . ["," ")"])) @reference.inherit
(attribute . (identifier) @match.derive arguments: (token_tree "," . (identifier) @name . ["," ")"])) @reference.inherit

; Imports. A use list is recorded as one import per member, with the path
; before the list as the source. A member that is itself a group is kept as
; written.
(use_declaration argument: (identifier) @import.source) @import
(use_declaration argument: (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @import.source name: (identifier) @import.name)) @import
(use_declaration argument: (use_as_clause path: (identifier) @import.source alias: (identifier) @import.alias)) @import
(use_declaration argument: (use_as_clause path: (scoped_identifier path: [(identifier) (scoped_identifier) (crate) (self) (super)] @import.source name: (identifier) @import.name) alias: (identifier) @import.alias)) @import
(use_declaration argument: (use_wildcard [(identifier) (scoped_identifier) (crate) (self) (super)] @import.source "*" @import.name)) @import
(use_declaration argument: (scoped_use_list path: [(identifier) (scoped_identifier) (crate) (self) (super)] @import.source list: (use_list [(identifier) (self) (scoped_identifier) (use_wildcard) (scoped_use_list)] @import.name))) @import
(use_declaration argument: (scoped_use_list path: [(identifier) (scoped_identifier) (crate) (self) (super)] @import.source list: (use_list (use_as_clause path: [(identifier) (self) (scoped_identifier)] @import.name alias: (identifier) @import.alias)))) @import
(extern_crate_declaration name: (identifier) @import.source) @import
(extern_crate_declaration name: (identifier) @import.source alias: (identifier) @import.alias) @import
