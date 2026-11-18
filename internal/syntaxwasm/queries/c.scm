; C query pack. Capture vocabulary: docs/syntax-analysis.md.
; The patterns for declarations repeat for each place a declaration can sit.

; Preprocessor definitions.
(preproc_def name: (identifier) @name) @definition.macro
(preproc_function_def name: (identifier) @name) @definition.macro

; Aggregate and enumeration types. An anonymous aggregate takes the name of its typedef.
(struct_specifier name: (type_identifier) @name body: (_)) @definition.struct
(union_specifier name: (type_identifier) @name body: (_)) @definition.struct
(enum_specifier name: (type_identifier) @name body: (_)) @definition.enum
(type_definition type: (struct_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.struct
(type_definition type: (union_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.struct
(type_definition type: (enum_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.enum
(enumerator name: (identifier) @name) @definition.constant

; Typedefs. The alias of a typedef that defines a tagged type is recorded on its own name.
(type_definition type: [(primitive_type) (sized_type_specifier) (type_identifier) (struct_specifier !body) (union_specifier !body) (enum_specifier !body) (macro_type_specifier)] declarator: [(type_identifier) @name (_ declarator: (type_identifier) @name) (_ declarator: (_ declarator: (type_identifier) @name)) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (type_identifier) @name)))]) @definition.type
(type_definition type: [(struct_specifier name: (_) body: (_)) (union_specifier name: (_) body: (_)) (enum_specifier name: (_) body: (_))] declarator: (type_identifier) @name @definition.type)
(type_definition type: [(struct_specifier body: (_)) (union_specifier body: (_)) (enum_specifier body: (_))] declarator: [(_ declarator: (type_identifier) @name @definition.type) (_ declarator: (_ declarator: (type_identifier) @name @definition.type)) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (type_identifier) @name @definition.type)))])

; Function definitions. A definition needs a return type: a macro invocation followed by a block is not one.
(function_definition type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function
; A function that returns a pointer to a function.
(function_definition type: (_) declarator: (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (function_declarator declarator: (identifier) @name))))) @definition.function

; A function-like block without a return type is a macro invocation. Its arguments are not types.
(translation_unit (function_definition !type declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @opaque)) @reference.call)
(declaration_list (function_definition !type declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @opaque)) @reference.call)
; A declaration whose declarator is in parentheses is a macro invocation in the position of a type.
(declaration type: (type_identifier) @opaque declarator: (parenthesized_declarator))
(declaration type: (type_identifier) @name declarator: (parenthesized_declarator)) @reference.call

; Function declarations.
(translation_unit (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)
(declaration_list (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)
(preproc_if (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)
(preproc_ifdef (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)
(preproc_else (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)
(translation_unit (declaration type: (_) declarator: (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (function_declarator declarator: (identifier) @name))))) @definition.function)
(declaration_list (declaration type: (_) declarator: (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (function_declarator declarator: (identifier) @name))))) @definition.function)
(linkage_specification body: (declaration type: (_) declarator: [(function_declarator declarator: (identifier) @name) (_ (function_declarator declarator: (identifier) @name))]) @definition.function)

; Variables of a file or namespace. The finisher makes the const ones constants.
(translation_unit (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (array_declarator declarator: (identifier) @name))))]) @definition.variable)
(declaration_list (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (array_declarator declarator: (identifier) @name))))]) @definition.variable)
(preproc_if (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name)))]) @definition.variable)
(preproc_ifdef (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name)))]) @definition.variable)
(preproc_else (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name)))]) @definition.variable)
(linkage_specification body: (declaration declarator: [(identifier) @name (_ declarator: (identifier) @name) (_ declarator: (_ declarator: (identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name)))]) @definition.variable)

; Members of structs, unions and classes.
(field_declaration declarator: [(field_identifier) @name (_ declarator: (field_identifier) @name) (_ declarator: (_ declarator: (field_identifier) @name)) (_ declarator: (_ declarator: (_ declarator: (field_identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (field_identifier) @name))) (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (array_declarator declarator: (field_identifier) @name))))]) @definition.field

; Calls. A call whose receiver is more than a short chain is recorded without a qualifier.
(call_expression function: [(identifier) @name (field_expression argument: [(identifier) (field_expression argument: (identifier)) (field_expression argument: (field_expression argument: (identifier)))] @qualifier field: (field_identifier) @name) (field_expression field: (field_identifier) @name)]) @reference.call

; Type uses.
(_ type: (type_identifier) @name @reference.type)
(struct_specifier name: (type_identifier) @name !body) @reference.type
(union_specifier name: (type_identifier) @name !body) @reference.type
(enum_specifier name: (type_identifier) @name !body) @reference.type

; Attributes.
(attribute !prefix name: (identifier) @name) @reference.decorator
(attribute prefix: (identifier) @qualifier name: (identifier) @name) @reference.decorator
(attribute_specifier (argument_list [(identifier) @name (call_expression function: (identifier) @name)])) @reference.decorator
(ms_declspec_modifier (identifier) @name) @reference.decorator

; Includes. A system include keeps its angle brackets; a quoted one is the text inside the quotes.
(preproc_include path: [(string_literal (string_content) @import.source) (system_lib_string) @import.source]) @import
