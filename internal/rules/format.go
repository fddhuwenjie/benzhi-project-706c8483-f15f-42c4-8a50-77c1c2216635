package rules

import "strconv"

func strconvFormat(value float64) string { return strconv.FormatFloat(value, 'f', 2, 64) }
