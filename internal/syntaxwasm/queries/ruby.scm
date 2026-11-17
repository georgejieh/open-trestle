; Ruby query pack. Capture vocabulary: docs/syntax-analysis.md.
; Methods are recorded as functions, and a function directly inside a class
; becomes a method. Visibility is applied by finishRuby. Definitions made
; by calls such as attr_accessor or define_method name a symbol, which the
; queries cannot record without its colon, so they are not recorded.

; Modules, classes and singleton classes. A singleton class (class << self)
; is recorded so that its methods have a parent; finishRuby removes it.
(module name: (constant) @name) @definition.module
(module name: (scope_resolution name: (constant) @name)) @definition.module
(class name: (constant) @name) @definition.class
(class name: (scope_resolution name: (constant) @name)) @definition.class
(singleton_class value: [(self) (identifier) (constant)] @name) @definition.class

; Methods and aliases.
(method name: (_) @name) @definition.function
(singleton_method name: (_) @name) @definition.function
(alias name: (identifier) @name) @definition.function

; Constants. A constant bound to a class or module factory is a type.
(assignment left: (constant) @name) @definition.constant
(assignment left: (scope_resolution name: (constant) @name)) @definition.constant
(assignment left: (constant) @name right: (call receiver: (constant) @match.Struct method: (identifier) @match.new)) @definition.class
(assignment left: (constant) @name right: (call receiver: (constant) @match.Class method: (identifier) @match.new)) @definition.class
(assignment left: (constant) @name right: (call receiver: (constant) @match.Data method: (identifier) @match.define)) @definition.class
(assignment left: (constant) @name right: (call receiver: (constant) @match.Module method: (identifier) @match.new)) @definition.module

; Globals at file level and class variables in a class or module body.
(program (assignment left: (global_variable) @name) @definition.variable)
(class body: (body_statement (assignment left: (class_variable) @name) @definition.field))
(module body: (body_statement (assignment left: (class_variable) @name) @definition.field))

; Calls. A bare identifier is not recorded, since it may be a local
; variable, except for the visibility keywords that finishRuby reads.
(call receiver: [(identifier) (constant) (self) (scope_resolution) (instance_variable) (class_variable) (global_variable)]? @qualifier method: [(identifier) (constant)] @name) @reference.call
(body_statement (identifier) @match.private @name @reference.call)
(body_statement (identifier) @match.protected @name @reference.call)
(body_statement (identifier) @match.public @name @reference.call)
(body_statement (identifier) @match.module_function @name @reference.call)

; Constructions.
(call receiver: [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)] method: (identifier) @match.new) @reference.construct

; Superclasses, mixins and rescued types.
(superclass [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)]) @reference.inherit
(call !receiver method: (identifier) @match.include arguments: (argument_list [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)])) @reference.inherit
(call !receiver method: (identifier) @match.extend arguments: (argument_list [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)])) @reference.inherit
(call !receiver method: (identifier) @match.prepend arguments: (argument_list [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)])) @reference.inherit
(exceptions [(constant) @name (scope_resolution scope: [(constant) (scope_resolution)] @qualifier name: (constant) @name)]) @reference.type

; Loading files.
(call !receiver method: (identifier) @match.require arguments: (argument_list . (string . (string_content) @import.source .) .)) @import
(call !receiver method: (identifier) @match.require_relative arguments: (argument_list . (string . (string_content) @import.source .) .)) @import
(call !receiver method: (identifier) @match.load arguments: (argument_list . (string . (string_content) @import.source .) .)) @import
(call !receiver method: (identifier) @match.autoload arguments: (argument_list . (simple_symbol) . (string . (string_content) @import.source .) .)) @import
