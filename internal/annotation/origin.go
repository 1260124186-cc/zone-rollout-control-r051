package annotation

// Origin captures the operational facts about the channel through which an
// annotation was recorded. The actor and finding live on the annotation
// itself; Origin is transport-level audit context assigned by the server.
type Origin struct {
	Source    string
	RequestID string
}
