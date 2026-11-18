; HTML query pack. Capture vocabulary: docs/syntax-analysis.md.
; An element with an id attribute is recorded as a variable named by the
; id, over its start tag, so that the code of a script inside the element
; stays at file level. Every tag name is recorded as a construction, and
; filterHTML keeps only custom element names. Targets are recorded as
; imports: src, href and action. Attribute names match in any case. The
; text of a script is embedded code, analysed with the pack its start tag
; names; style text is not analysed.

; Inline scripts.
(script_element (start_tag) @embedded.tag (raw_text) @embedded)

; Element ids.
(start_tag (attribute (attribute_name) @nocase.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)])) @definition.variable
(self_closing_tag (attribute (attribute_name) @nocase.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)])) @definition.variable

; Tag names, for custom elements.
(start_tag (tag_name) @name) @reference.construct
(self_closing_tag (tag_name) @name) @reference.construct

; Targets.
(attribute (attribute_name) @nocase.src [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @nocase.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @nocase.action [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
