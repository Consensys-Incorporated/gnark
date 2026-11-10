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

// Add sets v to a + b.
func (v *Vector) Add(a, b Vector) {
	for i := range *v {
		(*v)[i].Add(&a[i], &b[i])
	}
}

// Sub sets v to a - b.
func (v *Vector) Sub(a, b Vector) {
	for i := range *v {
		(*v)[i].Sub(&a[i], &b[i])
	}
}

// Mul sets v to the entrywise product of a and b.
func (v *Vector) Mul(a, b Vector) {
	for i := range *v {
		(*v)[i].Mul(&a[i], &b[i])
	}
}

// Neg sets v to -a.
func (v *Vector) Neg(a Vector) {
	for i := range *v {
		(*v)[i].Neg(&a[i])
	}
}

// ScalarMul sets v to a * c.
func (v *Vector) ScalarMul(a Vector, c *Element) {
	for i := range *v {
		(*v)[i].Mul(&a[i], c)
	}
}

// ScalarAdd sets v to a + c.
func (v *Vector) ScalarAdd(a Vector, c *Element) {
	for i := range *v {
		(*v)[i].Add(&a[i], c)
	}
}

// ScalarSub sets v to a - c.
func (v *Vector) ScalarSub(a Vector, c *Element) {
	for i := range *v {
		(*v)[i].Sub(&a[i], c)
	}
}

// ScalarSubFrom sets v to c - a.
func (v *Vector) ScalarSubFrom(c *Element, a Vector) {
	for i := range *v {
		(*v)[i].Sub(c, &a[i])
	}
}
