; C++ query pack. Capture vocabulary: docs/syntax-analysis.md.
; Declarations match wherever they sit. Blocks and friend declarations are
; local spans, so the variables and function declarations inside them are
; dropped before assembly.

; Preprocessor definitions.
(preproc_def name: (identifier) @name) @definition.macro
(preproc_function_def name: (identifier) @name) @definition.macro

; Aggregate and enumeration types. An anonymous aggregate takes the name of its typedef.
(struct_specifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)] body: (_)) @definition.struct
(union_specifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)] body: (_)) @definition.struct
(enum_specifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)] body: (_)) @definition.enum
(class_specifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)] body: (_)) @definition.class
(type_definition type: (struct_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.struct
(type_definition type: (union_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.struct
(type_definition type: (enum_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.enum
(type_definition type: (class_specifier !name body: (_)) declarator: (type_identifier) @name) @definition.class
(enumerator name: (identifier) @name) @definition.constant

; Typedefs. The alias of a typedef that defines a tagged type is recorded on its own name.
(type_definition
  type: [(primitive_type) (sized_type_specifier) (type_identifier) (struct_specifier !body) (union_specifier !body)
         (enum_specifier !body) (qualified_identifier) (template_type) (class_specifier !body) (decltype) (dependent_type)]
  declarator: [(type_identifier) @name
               (_ declarator: (type_identifier) @name)
               (_ declarator: (_ declarator: (type_identifier) @name))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (type_identifier) @name)))]) @definition.type
(type_definition
  type: [(struct_specifier name: (_) body: (_)) (union_specifier name: (_) body: (_)) (enum_specifier name: (_) body: (_)) (class_specifier name: (_) body: (_))]
  declarator: (type_identifier) @name @definition.type)
(type_definition
  type: [(struct_specifier body: (_)) (union_specifier body: (_)) (enum_specifier body: (_)) (class_specifier body: (_))]
  declarator: [(_ declarator: (type_identifier) @name @definition.type)
               (_ declarator: (_ declarator: (type_identifier) @name @definition.type))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (type_identifier) @name @definition.type)))])

; Namespaces, aliases and concepts. An anonymous namespace is named by its keyword.
(namespace_definition name: [(namespace_identifier) @name (nested_namespace_specifier) @name]) @definition.module
(namespace_definition !name "namespace" @name) @definition.module
(alias_declaration name: (type_identifier) @name) @definition.type
(concept_definition name: (identifier) @name) @definition.type

; Function definitions. A definition needs a return type: a macro invocation
; followed by a block is not one. A name written as Owner::name, or
; Outer::Owner::name, records its innermost scope as the container.
(function_definition
  type: (_)
  declarator: [(function_declarator declarator: [(identifier) (field_identifier) (operator_name) (destructor_name)] @name)
               (_ (function_declarator declarator: [(identifier) (field_identifier) (operator_name) (destructor_name)] @name))
               (function_declarator declarator: (template_function name: (identifier) @name))
               (_ (function_declarator declarator: (template_function name: (identifier) @name)))]) @definition.function
(function_definition
  type: (_)
  declarator: [(function_declarator declarator: (qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)]))
               (_ (function_declarator declarator: (qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)])))
               (function_declarator declarator: (qualified_identifier name: (qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)])))
               (_ (function_declarator declarator: (qualified_identifier name: (qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)]))))]) @definition.function
; A function that returns a pointer to a function.
(function_definition type: (_) declarator: (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (function_declarator declarator: (identifier) @name))))) @definition.function
; Constructors and destructors have no return type: they are defined out of line or directly in a class.
(function_definition
  !type
  declarator: (function_declarator declarator: [(qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)])
               (qualified_identifier name: (qualified_identifier
                 scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)]
                 name: [(identifier) @name (operator_name) @name (destructor_name) @name (template_function name: (identifier) @name)]))])) @definition.function
(field_declaration_list (function_definition !type declarator: (function_declarator declarator: [(identifier) @name (destructor_name) @name])) @definition.function)
(template_declaration (function_definition !type declarator: (function_declarator declarator: [(identifier) @name (destructor_name) @name])) @definition.function)

; A function-like block without a return type is a macro invocation. Its arguments are not types.
(translation_unit (function_definition !type declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @opaque)) @reference.call)
(declaration_list (function_definition !type declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @opaque)) @reference.call)
; A declaration whose declarator is in parentheses is a macro invocation in the position of a type.
(declaration type: (type_identifier) @opaque declarator: (parenthesized_declarator))
(declaration type: (type_identifier) @name declarator: (parenthesized_declarator)) @reference.call

; Local spans: every block, including function and lambda bodies and a
; block after a macro invocation, and friend declarations.
(compound_statement) @local
(friend_declaration) @local

; Function declarations.
(declaration
  type: (_)
  declarator: [(function_declarator declarator: [(identifier) (operator_name)] @name)
               (_ (function_declarator declarator: [(identifier) (operator_name)] @name))
               (function_declarator declarator: (template_function name: (identifier) @name))
               (_ (function_declarator declarator: (template_function name: (identifier) @name)))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (function_declarator declarator: (identifier) @name))))]) @definition.function
(field_declaration_list (declaration declarator: (function_declarator declarator: [(identifier) @name (destructor_name) @name])) @definition.function)
(field_declaration
  type: (_)
  declarator: [(function_declarator declarator: [(field_identifier) (operator_name) (destructor_name)] @name)
               (_ (function_declarator declarator: [(field_identifier) (operator_name) (destructor_name)] @name))]) @definition.method

; Variables of a file or namespace. The finisher makes the const ones constants.
(declaration
  declarator: [(identifier) @name
               (_ declarator: (identifier) @name)
               (_ declarator: (_ declarator: (identifier) @name))
               (_ declarator: (_ declarator: (_ declarator: (identifier) @name)))
               (reference_declarator (identifier) @name)
               (init_declarator declarator: (reference_declarator (identifier) @name))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (identifier) @name)))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (array_declarator declarator: (identifier) @name))))]) @definition.variable
(declaration
  declarator: [(qualified_identifier scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)] name: (identifier) @name)
               (init_declarator declarator: (qualified_identifier scope: [(namespace_identifier) @container (template_type name: (type_identifier) @container)] name: (identifier) @name))]) @definition.variable

; Members of structs, unions and classes.
(field_declaration
  declarator: [(field_identifier) @name
               (_ declarator: (field_identifier) @name)
               (_ declarator: (_ declarator: (field_identifier) @name))
               (_ declarator: (_ declarator: (_ declarator: (field_identifier) @name)))
               (reference_declarator (field_identifier) @name)
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (field_identifier) @name)))
               (function_declarator declarator: (parenthesized_declarator (pointer_declarator declarator: (array_declarator declarator: (field_identifier) @name))))]) @definition.field

; Calls. A call whose receiver is more than a short chain is recorded without
; a qualifier. A qualified name records its innermost scope as the qualifier.
(call_expression
  function: [(identifier) @name
             (template_function name: (identifier) @name)
             (field_expression field: [(field_identifier) @name (template_method name: (field_identifier) @name)])
             (field_expression
               argument: [(identifier) (this) (field_expression argument: [(identifier) (this)]) (field_expression argument: (field_expression argument: [(identifier) (this)]))] @qualifier
               field: [(field_identifier) @name (template_method name: (field_identifier) @name)])]) @reference.call
(call_expression
  function: [(qualified_identifier name: [(identifier) @name (template_function name: (identifier) @name)])
             (qualified_identifier name: (qualified_identifier name: [(identifier) @name (template_function name: (identifier) @name)]))]) @reference.call
(call_expression
  function: [(qualified_identifier
               scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
               name: [(identifier) @name (template_function name: (identifier) @name)])
             (qualified_identifier name: (qualified_identifier
               scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
               name: [(identifier) @name (template_function name: (identifier) @name)]))
             (qualified_identifier name: (qualified_identifier name: (qualified_identifier
               scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
               name: [(identifier) @name (template_function name: (identifier) @name)])))]) @reference.call

; A local declaration with a parameter list is usually a variable initialised with
; arguments, which the grammar reads as a function declaration. Its names are not types.
(compound_statement (declaration declarator: (function_declarator parameters: (parameter_list) @opaque)))

; Constructions.
(new_expression type: [(type_identifier) @name (template_type name: (type_identifier) @name) (qualified_identifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)])]) @reference.construct
(compound_literal_expression type: [(type_identifier) @name (template_type name: (type_identifier) @name) (qualified_identifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)])]) @reference.construct
(declaration type: [(type_identifier) @name (template_type name: (type_identifier) @name) (qualified_identifier name: [(type_identifier) @name (template_type name: (type_identifier) @name)])] declarator: (init_declarator value: [(argument_list) (initializer_list)])) @reference.construct

; Type uses.
(_ type: [(type_identifier) @name @reference.type (template_type name: (type_identifier) @name @reference.type)])
(_ type: [(qualified_identifier
           scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
           name: [(type_identifier) @name @reference.type (template_type name: (type_identifier) @name @reference.type)])
         (qualified_identifier name: (qualified_identifier
           scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
           name: [(type_identifier) @name @reference.type (template_type name: (type_identifier) @name @reference.type)]))
         (qualified_identifier name: (qualified_identifier name: (qualified_identifier
           scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
           name: [(type_identifier) @name @reference.type (template_type name: (type_identifier) @name @reference.type)])))])
(enum_specifier base: (type_identifier) @name @reference.type)
(friend_declaration (type_identifier) @name @reference.type)
(struct_specifier name: (type_identifier) @name !body) @reference.type
(union_specifier name: (type_identifier) @name !body) @reference.type
(enum_specifier name: (type_identifier) @name !body) @reference.type
(class_specifier name: (type_identifier) @name !body) @reference.type

; Base classes.
(base_class_clause
  [(type_identifier) @name
   (template_type name: (type_identifier) @name)
   (qualified_identifier
     scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
     name: [(type_identifier) @name (template_type name: (type_identifier) @name)])
   (qualified_identifier name: (qualified_identifier
     scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
     name: [(type_identifier) @name (template_type name: (type_identifier) @name)]))
   (qualified_identifier name: (qualified_identifier name: (qualified_identifier
     scope: [(namespace_identifier) @qualifier (template_type name: (type_identifier) @qualifier)]
     name: [(type_identifier) @name (template_type name: (type_identifier) @name)])))]) @reference.inherit

; Attributes.
(attribute !prefix name: (identifier) @name) @reference.decorator
(attribute prefix: (identifier) @qualifier name: (identifier) @name) @reference.decorator
(attribute_specifier (argument_list [(identifier) @name (call_expression function: (identifier) @name)])) @reference.decorator
(ms_declspec_modifier (identifier) @name) @reference.decorator

; Includes. A system include keeps its angle brackets; a quoted one is the text inside the quotes.
(preproc_include path: [(string_literal (string_content) @import.source) (system_lib_string) @import.source]) @import

; Using declarations and namespace aliases.
(using_declaration [(identifier) (qualified_identifier)] @import.source) @import
(namespace_alias_definition name: (namespace_identifier) @import.alias . [(namespace_identifier) (nested_namespace_specifier)] @import.source) @import
