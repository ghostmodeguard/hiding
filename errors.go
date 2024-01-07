package ghostmodeguard

import (
	"fmt"
)

var (
	ErrBadPublicKey     = fmt.Errorf("can't parse public key")
	ErrCantReadMessage  = fmt.Errorf("can't read message")
	ErrContentIsNotJson = fmt.Errorf("cmessage content is not json")
)
