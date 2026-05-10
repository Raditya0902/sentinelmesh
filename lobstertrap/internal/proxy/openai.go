package proxy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coal/lobstertrap/internal/metadata"
)

// ChatMessage represents a single message in the OpenAI chat format.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest is the OpenAI chat completions request format.
type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	// Ollama /api/generate sends a top-level "prompt" string instead of messages.
	Prompt      string        `json:"prompt,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
	MaxTokens   *int          `json:"max_tokens,omitempty"`
	// Pointer so we can distinguish "explicitly false" from "omitted".
	// Ollama native endpoints default stream=true when the field is absent.
	Stream      *bool         `json:"stream,omitempty"`
	// Lobster Trap metadata headers (optional, from _lobstertrap field)
	LobsterTrap *metadata.RequestHeaders `json:"_lobstertrap,omitempty"`
	// Preserve other fields
	Extra map[string]any `json:"-"`
}

// ChatChoice represents a single choice in the response.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatCompletionResponse is the OpenAI chat completions response format.
type ChatCompletionResponse struct {
	ID         string                    `json:"id"`
	Object     string                    `json:"object"`
	Created    int64                     `json:"created"`
	Model      string                    `json:"model"`
	Choices    []ChatChoice              `json:"choices"`
	// Ollama /api/generate responds with a top-level "response" string.
	Response   string                    `json:"response,omitempty"`
	// Ollama /api/chat native format responds with a top-level "message" object.
	Message    *ChatMessage              `json:"message,omitempty"`
	Usage      *Usage                    `json:"usage,omitempty"`
	LobsterTrap *metadata.ResponseHeaders `json:"_lobstertrap,omitempty"`
}

// Usage tracks token usage.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ParseChatRequest parses an OpenAI chat completion request from JSON bytes.
func ParseChatRequest(data []byte) (*ChatCompletionRequest, error) {
	var req ChatCompletionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing chat request: %w", err)
	}
	return &req, nil
}

// ParseChatResponse parses an OpenAI chat completion response from JSON bytes.
func ParseChatResponse(data []byte) (*ChatCompletionResponse, error) {
	var resp ChatCompletionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing chat response: %w", err)
	}
	return &resp, nil
}

// ExtractPromptText extracts the full prompt text from all messages.
func ExtractPromptText(req *ChatCompletionRequest) string {
	if len(req.Messages) == 0 {
		return req.Prompt // Ollama /api/generate fallback
	}
	var parts []string
	for _, msg := range req.Messages {
		parts = append(parts, msg.Content)
	}
	return strings.Join(parts, "\n")
}

// ExtractResponseText extracts the text from a response for egress DPI.
// Priority: choices (OpenAI) → response string (Ollama /api/generate) → message (Ollama /api/chat).
// All choices are concatenated so sensitive data in choices[1+] cannot bypass inspection.
func ExtractResponseText(resp *ChatCompletionResponse) string {
	if len(resp.Choices) > 0 {
		var parts []string
		for _, c := range resp.Choices {
			if c.Message.Content != "" {
				parts = append(parts, c.Message.Content)
			}
		}
		return strings.Join(parts, "\n")
	}
	if resp.Response != "" {
		return resp.Response
	}
	if resp.Message != nil {
		return resp.Message.Content
	}
	return ""
}

// MakeDenyResponse creates a chat completion response with a deny message
// and optional Lobster Trap response headers.
func MakeDenyResponse(message string, model string, headers *metadata.ResponseHeaders) *ChatCompletionResponse {
	return &ChatCompletionResponse{
		ID:         "lobstertrap-deny",
		Object:     "chat.completion",
		Model:      model,
		LobsterTrap: headers,
		Choices: []ChatChoice{
			{
				Index: 0,
				Message: ChatMessage{
					Role:    "assistant",
					Content: message,
				},
				FinishReason: "stop",
			},
		},
	}
}

// injectLobsterTrapHeaders injects _lobstertrap response headers into raw
// backend response JSON without disturbing any other fields.
func injectLobsterTrapHeaders(respBody []byte, headers *metadata.ResponseHeaders) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, err
	}

	headerBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	raw["_lobstertrap"] = headerBytes

	return json.Marshal(raw)
}
