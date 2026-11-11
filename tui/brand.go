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

// AmbassadorBridgeCompactMark is the same silhouette in three lines for narrow
// headers such as `trestle init`: the two X-braced towers, the suspension
// cables leaving each tower and the deck. Every line is ASCII and the same
// width, so text can sit beside it.
var AmbassadorBridgeCompactMark = [3]string{
	"   |X|\\            /|X|   ",
	" __|X| \\___----___/ |X|__ ",
	"===|X|=|==|==|==|===|X|===",
}

func writeAmbassadorBridgeMark(builder *strings.Builder) {
	builder.WriteString(ambassadorBridgeMark)
}
