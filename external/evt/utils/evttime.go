package utils

import "time"

const layout = "Jan 2, 2006 at 3:04pm (MST)"
const apiTimeFormatLayout = "2006-01-02T15:04:00"

func In5Mins() string {
	t := time.Now().UTC()

	t = t.Add(5 * time.Minute)
	return t.Format(apiTimeFormatLayout)
}
