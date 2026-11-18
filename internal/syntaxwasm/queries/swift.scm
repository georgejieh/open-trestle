; Swift query pack. Capture vocabulary: docs/syntax-analysis.md.
;
; A declaration is exported when it carries `public` or `open`. Each
; pattern that can be exported comes twice: once for the definition and once
; with the modifier, whose match is kept only for those words. The two
; records describe one definition and are merged. Members of a protocol and
; of an enum take the visibility of their owner, and so do the members of an
; extension, which also takes `public` from its own modifier.

; Types. An extension is a class named after the type it extends, so that
; its functions are methods of that type.
(class_declaration declaration_kind: "class" name: (type_identifier) @name) @definition.class
(class_declaration declaration_kind: "actor" name: (type_identifier) @name) @definition.class
(class_declaration declaration_kind: "struct" name: (type_identifier) @name) @definition.struct
(class_declaration declaration_kind: "enum" name: (type_identifier) @name) @definition.enum
(class_declaration declaration_kind: "extension" name: (user_type (type_identifier) @name .)) @definition.class
(protocol_declaration name: (type_identifier) @name) @definition.interface
(typealias_declaration name: (type_identifier) @name) @definition.type
(associatedtype_declaration name: (type_identifier) @name) @definition.type

(class_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) declaration_kind: "class" name: (type_identifier) @name) @definition.class
(class_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) declaration_kind: "actor" name: (type_identifier) @name) @definition.class
(class_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) declaration_kind: "struct" name: (type_identifier) @name) @definition.struct
(class_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) declaration_kind: "enum" name: (type_identifier) @name) @definition.enum
(class_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) declaration_kind: "extension" name: (user_type (type_identifier) @name .)) @definition.class
(protocol_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: (type_identifier) @name) @definition.interface
(typealias_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: (type_identifier) @name) @definition.type

; Functions, initializers, subscripts and operators. The name of an
; initializer is `init`, of a deinitializer `deinit` and of a subscript
; `subscript`.
(function_declaration "func" . name: _ @name) @definition.function
(function_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) "func" . name: _ @name) @definition.function
(protocol_function_declaration "func" . name: _ @name) @definition.function
(init_declaration name: "init" @name) @definition.constructor
(init_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: "init" @name) @definition.constructor
(deinit_declaration "deinit" @name) @definition.method
(subscript_declaration "subscript" @name) @definition.method
(subscript_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) "subscript" @name) @definition.method

; Enum cases.
(enum_entry name: (simple_identifier) @name) @definition.constant

; Properties. At the top of a file a `let` is a constant and a `var` a
; variable. In a type a property is a field, and a static `let` is a
; constant. A pattern binding several names defines each of them.
(source_file (property_declaration name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.variable)
(source_file (property_declaration (value_binding_pattern "let") name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.constant)
(source_file (property_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.variable)
(source_file (property_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) (value_binding_pattern "let") name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.constant)
(class_body (property_declaration name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.field)
(class_body (property_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.field)
(class_body (property_declaration (modifiers (property_modifier "static")) (value_binding_pattern "let") name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.constant)
(enum_class_body (property_declaration name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.field)
(enum_class_body (property_declaration (modifiers [(visibility_modifier "public") @match.public (visibility_modifier "open") @match.open] @exported) name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.field)
(enum_class_body (property_declaration (modifiers (property_modifier "static")) (value_binding_pattern "let") name: (pattern [(simple_identifier) @name (pattern (simple_identifier) @name)])) @definition.constant)
(protocol_body (protocol_property_declaration name: (pattern bound_identifier: (simple_identifier) @name)) @definition.field)

; Calls. A call of a type name is a construction, which the syntax cannot
; tell from a call of a function, so both are calls. The grammar also reads
; a subscript as a call with bracketed arguments; only parenthesized
; arguments and trailing closures make a call.
(call_expression . (simple_identifier) @name (call_suffix [(value_arguments "(") (lambda_literal)])) @reference.call
(call_expression . (navigation_expression suffix: (navigation_suffix suffix: (simple_identifier) @name)) (call_suffix [(value_arguments "(") (lambda_literal)])) @reference.call
(call_expression . (navigation_expression target: [(simple_identifier) (self_expression) (super_expression) (navigation_expression)] @qualifier suffix: (navigation_suffix suffix: (simple_identifier) @name)) (call_suffix [(value_arguments "(") (lambda_literal)])) @reference.call

; A generic type construction is read as a constructor expression.
(constructor_expression constructed_type: (user_type (type_identifier) @name .)) @reference.construct
(constructor_expression constructed_type: (user_type (type_identifier) @name . (type_arguments))) @reference.construct

; Types, conformances and attributes. A type written with one qualifier
; keeps it.
(user_type (type_identifier) @name .) @reference.type
(user_type (type_identifier) @name . (type_arguments)) @reference.type
(user_type . (type_identifier) @qualifier . (type_identifier) @name .) @reference.type
(user_type . (type_identifier) @qualifier . (type_identifier) @name . (type_arguments)) @reference.type
(inheritance_specifier inherits_from: (user_type (type_identifier) @name .)) @reference.inherit
(inheritance_specifier inherits_from: (user_type (type_identifier) @name . (type_arguments))) @reference.inherit
(inheritance_specifier inherits_from: (user_type . (type_identifier) @qualifier . (type_identifier) @name .)) @reference.inherit
(attribute (user_type (type_identifier) @name .)) @reference.decorator
(attribute (user_type (type_identifier) @name . (type_arguments))) @reference.decorator

; Imports. A kind keyword limits the import to one declaration of the
; module, which is then the name. The finishing step drops the whole-path
; record of such an import.
(import_declaration "import" . (identifier) @import.source) @import
(import_declaration ["typealias" "struct" "class" "enum" "protocol" "let" "var" "func"] (identifier . (simple_identifier) @import.source . (simple_identifier) @import.name .)) @import
