package iambridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
)

// FileState holds the bridge's durable publication journal. A process must
// hold its exclusive lock while reading, signing, sending, and saving state.
type FileState struct {
	Path      string
	lock      *os.File
	priorLock bool
}

func (s *FileState) Lock() error {
	if s.lock != nil {
		return errors.New("IAM bridge state is already locked")
	}
	lock, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return fmt.Errorf("another IAM bridge writer owns this state: %w", err)
	}
	s.lock = lock
	info, err := lock.Stat()
	if err != nil {
		_ = s.Close()
		return err
	}
	s.priorLock = info.Size() > 0
	return nil
}

func (s *FileState) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *FileState) Load() (State, error) {
	if s.lock == nil {
		return State{}, errors.New("IAM bridge state lock is required")
	}
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		if s.priorLock {
			return State{}, errors.New("IAM bridge state disappeared after initialization")
		}
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode IAM bridge state: %w", err)
	}
	return state, nil
}

func (s *FileState) Save(state State) error {
	if s.lock == nil {
		return errors.New("IAM bridge state lock is required")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".iam-bridge-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return err
	}
	if !s.priorLock {
		if _, err := s.lock.WriteAt([]byte("initialized\n"), 0); err != nil {
			return err
		}
		if err := s.lock.Sync(); err != nil {
			return err
		}
		s.priorLock = true
	}
	return nil
}

// Unblock requires the operator to confirm the receiver's checkpointed
// accepted sequence before a fresh IAM snapshot can be published again.
func (s *FileState) Unblock(acceptedSequence, maxObservedSequence int64) error {
	state, err := s.Load()
	if err != nil {
		return err
	}
	if state.Sequence != acceptedSequence || state.Pending == nil || !state.Pending.Blocked ||
		maxObservedSequence < acceptedSequence || maxObservedSequence == math.MaxInt64 {
		return errors.New("IAM bridge blocked state or accepted sequence does not match")
	}
	state.Pending.Blocked = false
	state.Pending.NeedsRefresh = true
	if next := max(state.Pending.Sequence, maxObservedSequence+1); next != state.Pending.Sequence {
		// Wires signed at the old sequence cannot prove acceptance of the new one.
		state.Pending.Sequence, state.Pending.Digests = next, nil
	}
	return s.Save(state)
}
