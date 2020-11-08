/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  huangweijun@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package common

import (
	"fmt"
)

var (
	Version string
	Commit string
	Date string
)

func SetVersion(version, commit, date string) {
	fmt.Printf("Version: %v\n", version)
	fmt.Printf("Commit: %v\n", commit)
	fmt.Printf("Date: %v\n", date)
	Version = version
	Commit = commit
	Date = date
}

func GetVersion() (string, string, string) {
	return Version, Commit, Date
}

