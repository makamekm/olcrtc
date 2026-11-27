package carrier

import (
	"context"

	"github.com/pion/webrtc/v4"
)

// ByteStream is a carrier capability for bidirectional byte transport.
type ByteStream interface {
	Connect(ctx context.Context) error
	Send(data []byte) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
}

// ReconnectRequester is an optional capability for rejoining a stalled carrier.
type ReconnectRequester interface {
	RequestReconnect() bool
}

// VideoTrack is a carrier capability for bidirectional video transport.
type VideoTrack interface {
	Connect(ctx context.Context) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
	AddTrack(track webrtc.TrackLocal) error
	SetTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver))
}
