package tui

import "strings"

// ambassadorBridgeMark is an original ASCII silhouette of the Ambassador Bridge.
// It uses the X-braced towers and suspension span without the tower lettering.
// Its fixed width fits the minimum supported terminal width.
const ambassadorBridgeMark = `       |X|\                     /|X|
    __/|X| \__               __/ |X|\__
 __/   |X| |  \____-----____/  |  |X|   \__
=======|X|=|==|==|==|==|==|==|==|=|X|=======
`

func writeAmbassadorBridgeMark(builder *strings.Builder) {
	builder.WriteString(ambassadorBridgeMark)
}
