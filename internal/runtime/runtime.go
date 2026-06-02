package runtime

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/fullsend-ai/fullsend/internal/ui"
)

// RunMetrics collects execution statistics from stream parsing.
type RunMetrics struct {
	ToolCalls atomic.Int32
}

// RunParams configures a single agent invocation inside the sandbox.
type RunParams struct {
	SandboxName   string
	AgentBaseName string
	Model         string
	RepoDir       string
	PluginDirs    []string
	Debug         string
	Timeout       time.Duration
}

// TranscriptError holds extracted error information from a runtime transcript.
type TranscriptError struct {
	Source       string
	IsError      bool
	ErrorMessage string
	Subtype      string
}

// Runtime is an agent execution backend (LLM tool-use loop) inside the sandbox.
// TODO: split transcript/debug helpers before adding a second runtime implementation.
type Runtime interface {
	Name() string
	ConfigDir() string
	EnvExports() []string
	Bootstrap(input BootstrapInput) error
	Run(params RunParams, printer *ui.Printer, start time.Time, metrics *RunMetrics) (exitCode int, err error)
	ClearIterationArtifacts(sandboxName string) error
	ExtractTranscripts(sandboxName, agentLabel, outputDir string) error
	ExtractDebugLog(sandboxName, localPath, debug string) error
	ParseTranscriptErrors(transcriptDir string) []TranscriptError
	EmitTranscriptErrors(w io.Writer, summaries []TranscriptError)
}

// Default returns the configured agent runtime (Claude Code today).
func Default() Runtime {
	return ClaudeRuntime{}
}
