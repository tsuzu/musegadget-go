package noise

// The Noise transport, mirroring musegadget.noise.transport: after the XX
// handshake, HTTP-like requests and responses are framed as ServiceFrames,
// wrapped in ServiceRequest/ServiceResponse envelopes, chunked into
// NoiseTransportFrames and encrypted with the split cipher states. Any
// failure marks the transport dead; the cipher state is never reused.

var emptyAD = []byte{}

// EncryptedFrames is one request's worth of encrypted transport frames.
type EncryptedFrames struct {
	StreamID int64
	Frames   [][]byte
}

// DecryptedFrame is one decoded inbound frame; exactly one of Response,
// BodyChunk or Reset is set, per Kind.
type DecryptedFrame struct {
	Kind      string
	StreamID  int64
	Response  *ApplicationResponse
	BodyChunk *BodyChunk
	Reset     *Reset
}

// Transport encrypts and decrypts service frames over a Noise session.
type Transport struct {
	send         *CipherState
	recv         *CipherState
	decoder      *NoiseFrameDecoder
	nextStreamID int64
	dead         bool
}

// NewTransport creates a transport from the handshake's split states
// (send first, receive second).
func NewTransport(send, recv *CipherState) *Transport {
	return &Transport{send: send, recv: recv, decoder: NewNoiseFrameDecoder(), nextStreamID: 1}
}

// Dead reports whether the transport has failed.
func (t *Transport) Dead() bool { return t.dead }

func (t *Transport) assertAlive() error {
	if t.dead {
		return protocolErrorf("NoiseTransport: dead after prior failure")
	}
	return nil
}

// EncryptHTTPRequest sends a complete request (body included, end_body).
func (t *Transport) EncryptHTTPRequest(method, path string, body []byte, service any, headers []Header) (*EncryptedFrames, error) {
	return t.sendApplicationRequest(method, path, body, service, headers, true)
}

// StartStreamRequest sends a request head with no body yet (end_body false).
func (t *Transport) StartStreamRequest(method, path string, service any, headers []Header) (*EncryptedFrames, error) {
	return t.sendApplicationRequest(method, path, nil, service, headers, false)
}

func (t *Transport) sendApplicationRequest(method, path string, body []byte, service any, headers []Header, endBody bool) (*EncryptedFrames, error) {
	if err := t.assertAlive(); err != nil {
		return nil, err
	}
	svc, err := CoerceService(service)
	if err != nil {
		t.dead = true
		return nil, err
	}
	streamID := t.nextStreamID
	t.nextStreamID++
	frame := RequestFrame(streamID, &ApplicationRequest{
		Verb: method, Path: path, Headers: headers, Body: body, EndBody: endBody,
	})
	frames, err := t.encryptRequest(svc, frame)
	if err != nil {
		t.dead = true
		return nil, err
	}
	return &EncryptedFrames{StreamID: streamID, Frames: frames}, nil
}

// EncryptBodyChunk encrypts one body chunk for an open stream.
func (t *Transport) EncryptBodyChunk(streamID int64, data []byte, service any, endBody bool) ([][]byte, error) {
	if err := t.assertAlive(); err != nil {
		return nil, err
	}
	svc, err := CoerceService(service)
	if err != nil {
		t.dead = true
		return nil, err
	}
	frames, err := t.encryptRequest(svc, BodyChunkFrame(streamID, &BodyChunk{Data: data, EndBody: endBody}))
	if err != nil {
		t.dead = true
		return nil, err
	}
	return frames, nil
}

// EncryptReset encrypts a stream reset with the default (daemon service,
// CANCELLED code), as the link client uses it.
func (t *Transport) EncryptReset(streamID int64, reason string) ([][]byte, error) {
	return t.EncryptResetFull(streamID, nil, reason, ResetCancelled)
}

// EncryptResetFull encrypts a stream reset with an explicit service/code.
func (t *Transport) EncryptResetFull(streamID int64, service any, reason string, code ResetCode) ([][]byte, error) {
	if err := t.assertAlive(); err != nil {
		return nil, err
	}
	svc, err := CoerceService(service)
	if err != nil {
		t.dead = true
		return nil, err
	}
	frames, err := t.encryptRequest(svc, ResetFrame(streamID, &Reset{Code: code, Reason: reason}))
	if err != nil {
		t.dead = true
		return nil, err
	}
	return frames, nil
}

// DecryptFrame decrypts and decodes one inbound WebSocket message. It
// returns (nil, nil) while a chunked envelope is incomplete.
func (t *Transport) DecryptFrame(ciphertext []byte) (*DecryptedFrame, error) {
	if err := t.assertAlive(); err != nil {
		return nil, err
	}
	frame, err := t.decryptFrame(ciphertext)
	if err != nil {
		t.dead = true
		return nil, err
	}
	return frame, nil
}

func (t *Transport) decryptFrame(ciphertext []byte) (*DecryptedFrame, error) {
	plainFrame, err := t.recv.DecryptWithAD(emptyAD, ciphertext)
	if err != nil {
		return nil, err
	}
	reassembled, err := t.decoder.Decode(plainFrame)
	if err != nil {
		return nil, err
	}
	if reassembled == nil {
		return nil, nil
	}
	response, err := DecodeServiceResponse(reassembled)
	if err != nil {
		return nil, err
	}
	if len(response.Payload) == 0 {
		return nil, protocolErrorf("empty ServiceResponse payload")
	}
	frame, err := DecodeServiceFrame(response.Payload)
	if err != nil {
		return nil, err
	}
	switch frame.Kind {
	case FrameResponse:
		if frame.Response == nil {
			return nil, protocolErrorf("invalid response frame")
		}
		return &DecryptedFrame{Kind: FrameResponse, StreamID: frame.StreamID, Response: frame.Response}, nil
	case FrameBodyChunk:
		if frame.BodyChunk == nil {
			return nil, protocolErrorf("invalid body_chunk frame")
		}
		return &DecryptedFrame{Kind: FrameBodyChunk, StreamID: frame.StreamID, BodyChunk: frame.BodyChunk}, nil
	case FrameReset:
		if frame.Reset == nil {
			return nil, protocolErrorf("invalid reset frame")
		}
		return &DecryptedFrame{Kind: FrameReset, StreamID: frame.StreamID, Reset: frame.Reset}, nil
	case FrameRequest:
		return nil, protocolErrorf("NoiseTransport: unexpected request frame from server")
	}
	return nil, nil
}

func (t *Transport) encryptRequest(service ServiceType, frame *ServiceFrame) ([][]byte, error) {
	frameBytes, err := EncodeServiceFrame(frame)
	if err != nil {
		return nil, err
	}
	requestBytes, err := EncodeServiceRequest(&ServiceRequest{Service: service, Payload: frameBytes})
	if err != nil {
		return nil, err
	}
	protoFrames, err := EncodeNoiseFrames(requestBytes, nil)
	if err != nil {
		return nil, err
	}
	encrypted := make([][]byte, 0, len(protoFrames))
	for _, plain := range protoFrames {
		ct, err := t.send.EncryptWithAD(emptyAD, plain)
		if err != nil {
			return nil, err
		}
		encrypted = append(encrypted, ct)
	}
	return encrypted, nil
}

// DecodeRequestEnvelope decodes a ServiceRequest envelope into its frame
// (the receiving side's counterpart, for servers and tests).
func DecodeRequestEnvelope(data []byte) (*ServiceFrame, error) {
	request, err := DecodeServiceRequest(data)
	if err != nil {
		return nil, err
	}
	return DecodeServiceFrame(request.Payload)
}

// EncodeResponseEnvelope encodes a frame as a ServiceResponse envelope
// (for servers and tests).
func EncodeResponseEnvelope(frame *ServiceFrame) ([]byte, error) {
	frameBytes, err := EncodeServiceFrame(frame)
	if err != nil {
		return nil, err
	}
	return EncodeServiceResponse(&ServiceResponse{Payload: frameBytes})
}
