// Package berths allocates berths in the harbour.
//
// It keeps a simple in-memory table.
package berths

import (
	"errors"
	"fmt"
	log "github.com/example/harbour/log"
)

import "strings"

// ErrFull is returned when no berth is free.
var ErrFull = errors.New("harbour full")

type Berth struct {
	ID   int
	Size string
}

type Allocator interface {
	Allocate(size string) (*Berth, error)
}

func (b *Berth) String() string { return fmt.Sprintf("%d/%s", b.ID, strings.ToLower(b.Size)) }

func New() *Berth {
	log.Info("new berth") // TODO: real allocation
	return &Berth{}
}
