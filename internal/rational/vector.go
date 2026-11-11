package rational

type Vector []Element

func (v Vector) MustSetRandom() {
	for i := range v {
		v[i].MustSetRandom()
	}
}

// Sum returns the sum of the elements of v.
func (v *Vector) Sum() (res Element) {
	for i := range *v {
		res.Add(&res, &(*v)[i])
	}
	return
}
