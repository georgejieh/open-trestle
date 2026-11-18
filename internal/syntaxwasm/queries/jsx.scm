; JSX element uses, for the JavaScript and TSX grammars.

(jsx_opening_element name: (identifier) @name) @reference.construct
(jsx_self_closing_element name: (identifier) @name) @reference.construct
(jsx_opening_element name: (member_expression object: (identifier) @qualifier property: (property_identifier) @name)) @reference.construct
(jsx_self_closing_element name: (member_expression object: (identifier) @qualifier property: (property_identifier) @name)) @reference.construct
