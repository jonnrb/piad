package session

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

type SecretKey wgtypes.Key

func NewKey() (sk SecretKey, err error) {
	wk, err := wgtypes.GeneratePrivateKey()
	sk = SecretKey(wk)
	return
}

func (sk SecretKey) PublicKey() (pk PublicKey) {
	pk = PublicKey(wgtypes.Key(sk).PublicKey())
	return
}

type PublicKey wgtypes.Key

func (pk *PublicKey) UnmarshalText(text []byte) (err error) {
	wk, err := wgtypes.ParseKey(string(text))
	*pk = PublicKey(wk)
	return
}
