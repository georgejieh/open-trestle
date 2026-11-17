; HTML query pack. Capture vocabulary: docs/syntax-analysis.md.
; An element with an id attribute is recorded as a variable named by the id.
; Every tag name is recorded as a construction, and finishHTML keeps only
; custom element names. Targets are recorded as imports: src on any element,
; href on links, anchors, areas and SVG uses and images, action on forms,
; formaction and poster. Scripts and styles are not parsed for their own
; language.

; Element ids.
(element (_ (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable
(script_element (start_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable
(style_element (start_tag (attribute (attribute_name) @match.id [(attribute_value) @name (quoted_attribute_value (attribute_value) @name)]))) @definition.variable

; Tag names, for custom elements.
(start_tag (tag_name) @name) @reference.construct
(self_closing_tag (tag_name) @name) @reference.construct

; Targets.
(attribute (attribute_name) @match.src [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @match.action [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @match.formaction [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(attribute (attribute_name) @match.poster [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import
(_ (tag_name) @match.a (attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import)
(_ (tag_name) @match.link (attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import)
(_ (tag_name) @match.area (attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import)
(_ (tag_name) @match.use (attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import)
(_ (tag_name) @match.image (attribute (attribute_name) @match.href [(attribute_value) @import.source (quoted_attribute_value (attribute_value) @import.source)]) @import)
