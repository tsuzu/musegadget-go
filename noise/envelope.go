package noise

// The service envelope carried inside Noise transport frames, mirroring
// musegadget.noise.envelope: ServiceRequest/ServiceResponse wrap a
// ServiceFrame, which multiplexes HTTP-like requests and responses over
// numbered streams.

import "fmt"

// ServiceType selects the VM service a frame is addressed to.
type ServiceType int32

const (
	ServiceDaemon   ServiceType = 0
	ServiceSentinel ServiceType = 1
	ServiceVault    ServiceType = 2
	ServiceAuthd    ServiceType = 3
)

var serviceNames = map[string]ServiceType{
	"daemon":   ServiceDaemon,
	"sentinel": ServiceSentinel,
	"vault":    ServiceVault,
	"authd":    ServiceAuthd,
}

// CoerceService accepts a ServiceType or its name ("daemon", ...), as the
// reference transport does.
func CoerceService(service any) (ServiceType, error) {
	switch v := service.(type) {
	case nil:
		return ServiceDaemon, nil
	case ServiceType:
		return coerceServiceType(int32(v))
	case string:
		if st, ok := serviceNames[v]; ok {
			return st, nil
		}
		return 0, &ProtocolError{Message: fmt.Sprintf("unknown noise service: %s", v)}
	case int:
		return coerceServiceType(int32(v))
	case int32:
		return coerceServiceType(v)
	}
	return 0, &ProtocolError{Message: fmt.Sprintf("unknown noise service: %v", service)}
}

func coerceServiceType(value int32) (ServiceType, error) {
	switch ServiceType(value) {
	case ServiceDaemon, ServiceSentinel, ServiceVault, ServiceAuthd:
		return ServiceType(value), nil
	}
	return 0, protoErrorf("unknown service type")
}

// ResetCode is why a stream was reset.
type ResetCode int32

const (
	ResetCodeUnspecified    ResetCode = 0
	ResetCancelled          ResetCode = 1
	ResetTimeout            ResetCode = 2
	ResetProtocolError      ResetCode = 3
	ResetRefusedStream      ResetCode = 4
	ResetInternalError      ResetCode = 5
	ResetServiceUnavailable ResetCode = 6
)

func coerceResetCode(value int32) (ResetCode, error) {
	if value >= 0 && value <= 6 {
		return ResetCode(value), nil
	}
	return 0, protoErrorf("unknown reset code")
}

// Header is one HTTP header.
type Header struct {
	Key   string
	Value string
}

// ApplicationRequest is the head of a request stream.
type ApplicationRequest struct {
	Verb    string
	Path    string
	Headers []Header
	Body    []byte
	EndBody bool
}

// ApplicationResponse is the head of a response stream.
type ApplicationResponse struct {
	Status  int32
	Headers []Header
	Body    []byte
	EndBody bool
}

// BodyChunk continues a request or response stream.
type BodyChunk struct {
	Data    []byte
	EndBody bool
}

// Reset aborts a stream.
type Reset struct {
	Code   ResetCode
	Reason string
}

// Service frame kinds.
const (
	FrameRequest   = "request"
	FrameResponse  = "response"
	FrameBodyChunk = "body_chunk"
	FrameReset     = "reset"
)

// ServiceFrame is one multiplexed frame; exactly one of the value fields
// is set, per Kind.
type ServiceFrame struct {
	StreamID  int64
	Kind      string
	Request   *ApplicationRequest
	Response  *ApplicationResponse
	BodyChunk *BodyChunk
	Reset     *Reset
}

// RequestFrame builds a request ServiceFrame.
func RequestFrame(streamID int64, req *ApplicationRequest) *ServiceFrame {
	return &ServiceFrame{StreamID: streamID, Kind: FrameRequest, Request: req}
}

// ResponseFrame builds a response ServiceFrame.
func ResponseFrame(streamID int64, resp *ApplicationResponse) *ServiceFrame {
	return &ServiceFrame{StreamID: streamID, Kind: FrameResponse, Response: resp}
}

// BodyChunkFrame builds a body_chunk ServiceFrame.
func BodyChunkFrame(streamID int64, chunk *BodyChunk) *ServiceFrame {
	return &ServiceFrame{StreamID: streamID, Kind: FrameBodyChunk, BodyChunk: chunk}
}

// ResetFrame builds a reset ServiceFrame.
func ResetFrame(streamID int64, reset *Reset) *ServiceFrame {
	return &ServiceFrame{StreamID: streamID, Kind: FrameReset, Reset: reset}
}

// ServiceRequest wraps a frame for a service.
type ServiceRequest struct {
	Service ServiceType
	Payload []byte
}

// ServiceResponse wraps a frame coming back from a service.
type ServiceResponse struct {
	Payload []byte
}

func encodeHeader(h Header) ([]byte, error) {
	var out []byte
	var err error
	if h.Key != "" {
		if out, err = stringField(out, 1, h.Key); err != nil {
			return nil, err
		}
	}
	if h.Value != "" {
		if out, err = stringField(out, 2, h.Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func decodeHeader(data []byte) (Header, error) {
	var h Header
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return h, err
		}
		switch field {
		case 1:
			if h.Key, err = r.readStringField("Header.key", wt); err != nil {
				return h, err
			}
		case 2:
			if h.Value, err = r.readStringField("Header.value", wt); err != nil {
				return h, err
			}
		default:
			if err := r.skipField(wt); err != nil {
				return h, err
			}
		}
	}
	return h, nil
}

// EncodeApplicationRequest encodes a request head.
func EncodeApplicationRequest(req *ApplicationRequest) ([]byte, error) {
	var out []byte
	var err error
	if req.Verb != "" {
		if out, err = stringField(out, 1, req.Verb); err != nil {
			return nil, err
		}
	}
	if req.Path != "" {
		if out, err = stringField(out, 2, req.Path); err != nil {
			return nil, err
		}
	}
	for _, h := range req.Headers {
		encoded, err := encodeHeader(h)
		if err != nil {
			return nil, err
		}
		if out, err = delimitedField(out, 3, encoded); err != nil {
			return nil, err
		}
	}
	if len(req.Body) > 0 {
		if out, err = bytesField(out, 4, req.Body); err != nil {
			return nil, err
		}
	}
	if req.EndBody {
		if out, err = boolField(out, 5, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeApplicationRequest decodes a request head.
func DecodeApplicationRequest(data []byte) (*ApplicationRequest, error) {
	req := &ApplicationRequest{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			if req.Verb, err = r.readStringField("ApplicationRequest.verb", wt); err != nil {
				return nil, err
			}
		case 2:
			if req.Path, err = r.readStringField("ApplicationRequest.path", wt); err != nil {
				return nil, err
			}
		case 3:
			raw, err := r.readBytesField("ApplicationRequest.headers", wt)
			if err != nil {
				return nil, err
			}
			h, err := decodeHeader(raw)
			if err != nil {
				return nil, err
			}
			req.Headers = append(req.Headers, h)
		case 4:
			if req.Body, err = r.readBytesField("ApplicationRequest.body", wt); err != nil {
				return nil, err
			}
		case 5:
			raw, err := r.readVarintField("ApplicationRequest.end_body", wt)
			if err != nil {
				return nil, err
			}
			req.EndBody = raw != 0
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return req, nil
}

// EncodeApplicationResponse encodes a response head.
func EncodeApplicationResponse(resp *ApplicationResponse) ([]byte, error) {
	var out []byte
	var err error
	if resp.Status != 0 {
		if out, err = int32Field(out, 1, resp.Status); err != nil {
			return nil, err
		}
	}
	for _, h := range resp.Headers {
		encoded, err := encodeHeader(h)
		if err != nil {
			return nil, err
		}
		if out, err = delimitedField(out, 2, encoded); err != nil {
			return nil, err
		}
	}
	if len(resp.Body) > 0 {
		if out, err = bytesField(out, 3, resp.Body); err != nil {
			return nil, err
		}
	}
	if resp.EndBody {
		if out, err = boolField(out, 4, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeApplicationResponse decodes a response head.
func DecodeApplicationResponse(data []byte) (*ApplicationResponse, error) {
	resp := &ApplicationResponse{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			raw, err := r.readVarintField("ApplicationResponse.status", wt)
			if err != nil {
				return nil, err
			}
			status, err := decodeInt32(raw)
			if err != nil {
				return nil, err
			}
			resp.Status = status
		case 2:
			raw, err := r.readBytesField("ApplicationResponse.headers", wt)
			if err != nil {
				return nil, err
			}
			h, err := decodeHeader(raw)
			if err != nil {
				return nil, err
			}
			resp.Headers = append(resp.Headers, h)
		case 3:
			if resp.Body, err = r.readBytesField("ApplicationResponse.body", wt); err != nil {
				return nil, err
			}
		case 4:
			raw, err := r.readVarintField("ApplicationResponse.end_body", wt)
			if err != nil {
				return nil, err
			}
			resp.EndBody = raw != 0
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return resp, nil
}

// EncodeBodyChunk encodes a body chunk.
func EncodeBodyChunk(chunk *BodyChunk) ([]byte, error) {
	var out []byte
	var err error
	if len(chunk.Data) > 0 {
		if out, err = bytesField(out, 1, chunk.Data); err != nil {
			return nil, err
		}
	}
	if chunk.EndBody {
		if out, err = boolField(out, 2, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeBodyChunk decodes a body chunk.
func DecodeBodyChunk(data []byte) (*BodyChunk, error) {
	chunk := &BodyChunk{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			if chunk.Data, err = r.readBytesField("BodyChunk.data", wt); err != nil {
				return nil, err
			}
		case 2:
			raw, err := r.readVarintField("BodyChunk.end_body", wt)
			if err != nil {
				return nil, err
			}
			chunk.EndBody = raw != 0
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return chunk, nil
}

// EncodeReset encodes a stream reset.
func EncodeReset(reset *Reset) ([]byte, error) {
	code, err := coerceResetCode(int32(reset.Code))
	if err != nil {
		return nil, err
	}
	var out []byte
	if code != ResetCodeUnspecified {
		if out, err = int32Field(out, 1, int32(code)); err != nil {
			return nil, err
		}
	}
	if reset.Reason != "" {
		if out, err = stringField(out, 2, reset.Reason); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeReset decodes a stream reset.
func DecodeReset(data []byte) (*Reset, error) {
	reset := &Reset{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			raw, err := r.readVarintField("Reset.code", wt)
			if err != nil {
				return nil, err
			}
			code, err := decodeInt32(raw)
			if err != nil {
				return nil, err
			}
			coerced, err := coerceResetCode(code)
			if err != nil {
				return nil, err
			}
			reset.Code = coerced
		case 2:
			if reset.Reason, err = r.readStringField("Reset.reason", wt); err != nil {
				return nil, err
			}
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return reset, nil
}

// EncodeServiceFrame encodes one multiplexed frame.
func EncodeServiceFrame(frame *ServiceFrame) ([]byte, error) {
	var out []byte
	var err error
	if frame.StreamID != 0 {
		if out, err = int64Field(out, 1, frame.StreamID); err != nil {
			return nil, err
		}
	}
	switch frame.Kind {
	case "":
		if frame.Request != nil || frame.Response != nil || frame.BodyChunk != nil || frame.Reset != nil {
			return nil, protoErrorf("ServiceFrame value provided without kind")
		}
		return out, nil
	case FrameRequest:
		if frame.Request == nil {
			return nil, protoErrorf("ServiceFrame request value has wrong type")
		}
		encoded, err := EncodeApplicationRequest(frame.Request)
		if err != nil {
			return nil, err
		}
		return delimitedField(out, 2, encoded)
	case FrameResponse:
		if frame.Response == nil {
			return nil, protoErrorf("ServiceFrame response value has wrong type")
		}
		encoded, err := EncodeApplicationResponse(frame.Response)
		if err != nil {
			return nil, err
		}
		return delimitedField(out, 3, encoded)
	case FrameBodyChunk:
		if frame.BodyChunk == nil {
			return nil, protoErrorf("ServiceFrame body_chunk value has wrong type")
		}
		encoded, err := EncodeBodyChunk(frame.BodyChunk)
		if err != nil {
			return nil, err
		}
		return delimitedField(out, 4, encoded)
	case FrameReset:
		if frame.Reset == nil {
			return nil, protoErrorf("ServiceFrame reset value has wrong type")
		}
		encoded, err := EncodeReset(frame.Reset)
		if err != nil {
			return nil, err
		}
		return delimitedField(out, 5, encoded)
	}
	return nil, protoErrorf("unknown ServiceFrame kind")
}

// DecodeServiceFrame decodes one multiplexed frame.
func DecodeServiceFrame(data []byte) (*ServiceFrame, error) {
	frame := &ServiceFrame{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			raw, err := r.readVarintField("ServiceFrame.stream_id", wt)
			if err != nil {
				return nil, err
			}
			frame.StreamID = decodeInt64(raw)
		case 2:
			raw, err := r.readBytesField("ServiceFrame.request", wt)
			if err != nil {
				return nil, err
			}
			req, err := DecodeApplicationRequest(raw)
			if err != nil {
				return nil, err
			}
			frame.Kind, frame.Request = FrameRequest, req
		case 3:
			raw, err := r.readBytesField("ServiceFrame.response", wt)
			if err != nil {
				return nil, err
			}
			resp, err := DecodeApplicationResponse(raw)
			if err != nil {
				return nil, err
			}
			frame.Kind, frame.Response = FrameResponse, resp
		case 4:
			raw, err := r.readBytesField("ServiceFrame.body_chunk", wt)
			if err != nil {
				return nil, err
			}
			chunk, err := DecodeBodyChunk(raw)
			if err != nil {
				return nil, err
			}
			frame.Kind, frame.BodyChunk = FrameBodyChunk, chunk
		case 5:
			raw, err := r.readBytesField("ServiceFrame.reset", wt)
			if err != nil {
				return nil, err
			}
			reset, err := DecodeReset(raw)
			if err != nil {
				return nil, err
			}
			frame.Kind, frame.Reset = FrameReset, reset
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return frame, nil
}

// EncodeServiceRequest encodes a service request envelope.
func EncodeServiceRequest(request *ServiceRequest) ([]byte, error) {
	service, err := coerceServiceType(int32(request.Service))
	if err != nil {
		return nil, err
	}
	var out []byte
	if service != ServiceDaemon {
		if out, err = varintField(out, 1, uint64(int64(service))); err != nil {
			return nil, err
		}
	}
	if len(request.Payload) > 0 {
		if out, err = bytesField(out, 2, request.Payload); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeServiceRequest decodes a service request envelope.
func DecodeServiceRequest(data []byte) (*ServiceRequest, error) {
	request := &ServiceRequest{Service: ServiceDaemon}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			raw, err := r.readVarintField("ServiceRequest.service", wt)
			if err != nil {
				return nil, err
			}
			service, err := decodeInt32(raw)
			if err != nil {
				return nil, err
			}
			coerced, err := coerceServiceType(service)
			if err != nil {
				return nil, err
			}
			request.Service = coerced
		case 2:
			if request.Payload, err = r.readBytesField("ServiceRequest.payload", wt); err != nil {
				return nil, err
			}
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return request, nil
}

// EncodeServiceResponse encodes a service response envelope; an empty
// payload encodes to zero bytes.
func EncodeServiceResponse(response *ServiceResponse) ([]byte, error) {
	if len(response.Payload) == 0 {
		return []byte{}, nil
	}
	return bytesField(nil, 1, response.Payload)
}

// DecodeServiceResponse decodes a service response envelope.
func DecodeServiceResponse(data []byte) (*ServiceResponse, error) {
	response := &ServiceResponse{}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			if response.Payload, err = r.readBytesField("ServiceResponse.payload", wt); err != nil {
				return nil, err
			}
		default:
			if err := r.skipField(wt); err != nil {
				return nil, err
			}
		}
	}
	return response, nil
}
