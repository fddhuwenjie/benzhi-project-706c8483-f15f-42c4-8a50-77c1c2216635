package cases

type CommandName string

const (
	CommandVerify  CommandName = "verify"
	CommandPlan    CommandName = "plan"
	CommandReview  CommandName = "review"
	CommandExecute CommandName = "execute"
	CommandObserve CommandName = "observe"
	CommandReopen  CommandName = "reopen"
)
