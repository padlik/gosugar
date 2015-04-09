package gosugar

import (
	"encoding/json"
	"errors"
	"strings"
)

//Raw json structure representing Filter for JSON module query
type FilterJson struct {
	Filter  *json.RawMessage `json:"filter"`   //filer in JSON
	MaxNum  int              `json:"max_num"`  //Number of records to return at one go
	Offset  int              `json:"offset"`   //Offset to the next record bunch
	Fields  string           `json:"fields"`   //Fields
	View    string           `json:"view"`     //internal not used
	OrderBy string           `json:"order_by"` //order by string
	Q       string           `json:"q"`        //internal not used
	Deleted bool             `json:"deleted"`  //show deleted record
}

const returnmax = 1000
const sasc = ":ASC"
const sdesc = ":DESC"

type Sorting struct {
	//Lists of fields to sort by
	Asc  []string
	Desc []string
}

type Query struct {
	//Module to be queried
	Module string

	//Filter for module
	Filter *QueryFilter

	//Fields list. ID will always return
	Fields []string

	//Order by lists
	Sort Sorting

	//Query method (default POST)
	Method string

	//Maximum number of Records
	MaxNum int
}

func NewQuery(mod string) (*Query, error) {
	if len(mod) == 0 {
		return nil, errors.New("Empty module name")
	}
	q := &Query{Module: mod, Method: "POST", MaxNum: returnmax}
	return q, nil
}

func makeSort(s []string, p string) string {
	r := ""
	for k, _ := range s {
		r = r + s[k] + p
		if k < len(s)-1 {
			r = r + ","
		}
	}
	return r
}

//Implementing valid JSON part for query
func (q *Query) MarshalJSON() ([]byte, error) {
	fj := FilterJson{MaxNum: q.MaxNum, Deleted: false, Offset: 0}
	if q.Filter != nil {
		b, err := json.Marshal(q.Filter)
		if err != nil {
			return nil, err
		}
		raw := json.RawMessage(b)
		fj.Filter = &raw
	}

	//we can simple join fields
	fj.Fields = strings.Join(q.Fields, ",")

	//sorting
	sort := []string{makeSort(q.Sort.Asc, sasc), makeSort(q.Sort.Desc, sdesc)}
	fj.OrderBy = strings.Trim(strings.Join(sort, ","), ",")
	b, err := json.Marshal(fj)
	if err != nil {
		return nil, err
	}
	return b, nil
}
