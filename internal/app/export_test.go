package app

// SetTrapPolicyFailForTest makes applyTrapPolicy return err before
// ReplaceCaps. Compiled only with the app tests.
func (s *App) SetTrapPolicyFailForTest(err error) {
	if s == nil {
		return
	}
	s.trapPolicyFail = err
}
