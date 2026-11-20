# pion/sctp v1.9.4 with two olcrtc changes

olcrtc carries the direct path's KCP packets over an unordered, unreliable
WebRTC data channel; KCP repairs losses itself. Two pion/sctp behaviours
stalled that channel for seconds after packet loss:

- `rtoMin` 1 s (`rtx_timer.go`): lowered to 200 ms.
- Tail loss recovery burst limiting (`tlrBeginLocked` in `association.go`):
  off unless `OLCRTC_SCTP_TLR=1`.

Everything else is upstream v1.9.4 (MIT, see LICENSE).
