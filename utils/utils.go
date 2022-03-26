package utils

type Map map[string]interface{}

func (m Map) Get(key string) *MapValue {
	return &MapValue{
		v: m[key],
	}
}

func (m Map) Set(key string, value interface{}) {
	m[key] = value
}

func (m Map) CopyTo(dst Map) {
	for k, v := range m {
		dst[k] = v
	}
}

type MapValue struct {
	v interface{}
}

func (mv *MapValue) String() string {
	if v, ok := mv.v.(string); ok {
		return v
	}

	return ""
}

func (mv *MapValue) Int64() int64 {
	if v, ok := mv.v.(int64); ok {
		return v
	}

	return int64(mv.Float64())
}

func (mv *MapValue) Int() int {
	if v, ok := mv.v.(int); ok {
		return v
	}

	return 0
}

func (mv *MapValue) Bool() bool {
	if v, ok := mv.v.(bool); ok {
		return v
	}

	return false
}

func (mv *MapValue) Float64() float64 {
	if v, ok := mv.v.(float64); ok {
		return v
	}

	return 0
}
