; HTML query pack. Capture vocabulary: docs/syntax-analysis.md.
; An element with an id attribute is recorded as a variable named by the id.
; Every tag name is recorded as a construction, and filterHTML keeps only
; custom element names. Targets are recorded as imports: src, href and
; action. The text of a script is embedded code, analysed with the pack
; its start tag names; style text is not analysed.

; Inline scripts.
(script_element (start_tag) @embedded.tag (raw_text) @embedded)

; Element ids.
(element (start_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable
(element (self_closing_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable
(script_element (start_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable
(style_element (start_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable

; Tag names, for custom elements.
(start_tag (tag_name) @name) @reference.construct
(self_closing_tag (tag_name) @name) @reference.construct

; Targets.
(attribute (attribute_name) @match.src [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @match.action [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
