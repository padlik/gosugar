package gosugar

import "encoding/json"

//Interface to all filter elements
//Dump produces data for filter
type FilterElement interface {
	json.Marshaler
	Dump() map[string]interface{}
}

type QueryFilter struct {
	Data []FilterElement
}

//Group operator
//$or and $and are valid at the moment
type GroupOperator struct {
	Name string
	Data []FilterElement
}

func (f *QueryFilter) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(f.Data)
	if err != nil {
		return nil, err
	}
	return b, err
}

func (f *QueryFilter) Append(op ...FilterElement) {
	for _, v := range op {
		f.Data = append(f.Data, v)
	}
}

func (o *GroupOperator) Dump() map[string]interface{} {
	m := make(map[string]interface{})
	d := make([]map[string]interface{}, len(o.Data))
	for i := 0; i < len(o.Data); i++ {
		d[i] = o.Data[i].Dump()
	}
	m[o.Name] = d
	return m
}

func (o *GroupOperator) MarshalJSON() ([]byte, error) {
	d := o.Dump()
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return b, nil
}

//Append element to group operator
func (o *GroupOperator) Append(op ...FilterElement) {
	for _, v := range op {
		o.Data = append(o.Data, v)
	}
}

//Creates new and empty group operator
func MakeGroupOperator(name string) *GroupOperator {
	return &GroupOperator{Name: name}
}

type FieldOperator struct {
	OpName string      //operation name (e.g "$eq")
	Field  string      //operation field (e.g "name")
	Value  interface{} //operation value, typically string or empty string or array of strings
}

func (o *FieldOperator) Dump() map[string]interface{} {
	//field map
	fm := make(map[string]interface{})
	//operations map
	om := make(map[string]interface{})
	om[o.OpName] = o.Value
	fm[o.Field] = om
	return fm
}

func (f *FieldOperator) MarshalJSON() ([]byte, error) {
	d := f.Dump()
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func MakeFieldOperator(name string, field string, value interface{}) *FieldOperator {
	return &FieldOperator{name, field, value}
}
