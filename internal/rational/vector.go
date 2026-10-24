package rational

type Vector []Element

func (v Vector) MustSetRandom() {
	for i := range v {
		v[i].MustSetRandom()
	}
}
