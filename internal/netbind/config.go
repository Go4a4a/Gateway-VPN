package netbind

import "errors"

type Config struct {
	InterfaceName string
	Fwmark        uint32
}

func (configuration Config) Validate() error {
	if !validInterfaceName(configuration.InterfaceName) || configuration.Fwmark == 0 {
		return errors.New("valid interface and non-zero fwmark are required")
	}
	return nil
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}
