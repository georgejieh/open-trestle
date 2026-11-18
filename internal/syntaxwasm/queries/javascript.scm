; JavaScript-only patterns; ecmascript.scm holds the shared ones.

(class_declaration name: (identifier) @name) @definition.class
(class name: (identifier) @name) @definition.class
(export_statement declaration: (class_declaration name: (identifier) @name @exported) @definition.class)
(field_definition property: [(property_identifier) (private_property_identifier)] @name) @definition.field

(class_heritage (identifier) @name) @reference.inherit
(class_heritage (member_expression object: [(identifier) (member_expression)] @qualifier property: (property_identifier) @name)) @reference.inherit
(class_heritage (call_expression function: (identifier) @name)) @reference.inherit
