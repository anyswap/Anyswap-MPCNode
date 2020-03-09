/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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
	"sync"
)

type SafeMap struct {
	sync.RWMutex
	Map map[string]interface{}
}

func NewSafeMap(size int) *SafeMap {
	sm := new(SafeMap)
	sm.Map = make(map[string]interface{})
	return sm
}

func (sm *SafeMap) ReadMap(key string) (interface{}, bool) {
	sm.RLock()
	value, ok := sm.Map[key]
	sm.RUnlock()
	return value, ok
}

func (sm *SafeMap) WriteMap(key string, value interface{}) {
	sm.Lock()
	sm.Map[key] = value
	sm.Unlock()
}

func (sm *SafeMap) DeleteMap(key string) {
	sm.Lock()
	delete(sm.Map, key)
	sm.Unlock()
}

func (sm *SafeMap) ListMap() ([]string, []interface{}) {
	sm.RLock()
	l := len(sm.Map)
	key := make([]string, l)
	value := make([]interface{}, l)
	i := 0
	for k, v := range sm.Map {
		key[i] = k
		value[i] = v
		i++
	}
	sm.RUnlock()

	return key, value
}

func (sm *SafeMap) MapLength() int {
	sm.RLock()
	l := len(sm.Map)
	sm.RUnlock()
	return l
}
