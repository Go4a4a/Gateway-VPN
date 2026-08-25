package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func decodeStrictJSON(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON input must contain exactly one value")
	}
	return nil
}
