package authdetails

type AuthDetails struct {
	R          []byte
	S          []byte
	Additional []byte // Here as a optional helper.
}
