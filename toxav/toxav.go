package gtoxav

/*
#include <tox/toxav.h>

#define CBB(x) \
static void callback_##x(ToxAV* av) { \
	toxav_callback_##x(av, (toxav_##x##_cb*)&cb_##x, NULL); \
}

// wrapper cb functions
void cb_call(ToxAV*, uint32_t, bool, bool, void*);
void cb_call_state(ToxAV*, uint32_t, uint32_t, void*);
void cb_bit_rate_status(ToxAV*, uint32_t, uint32_t, uint32_t, void*);
void cb_audio_receive_frame(ToxAV*, uint32_t, int16_t*, size_t, uint8_t, uint32_t, void*);
void cb_video_receive_frame(ToxAV*, uint32_t, uint16_t, uint16_t, uint8_t*, uint8_t*, uint8_t*, int32_t, int32_t, int32_t, void*);

CBB(call)
CBB(call_state)
CBB(bit_rate_status)
CBB(audio_receive_frame)
CBB(video_receive_frame)
*/
import "C"
import (
	"errors"
	"unsafe"
	"reflect"
	"time"
	"sync"
	"context"
	. "github.com/xhebox/gtox/tox"
)

// ======== type and enum ==========
// call state graph
const (
	FRIEND_CALL_STATE_NONE = C.TOXAV_FRIEND_CALL_STATE_NONE
	FRIEND_CALL_STATE_ERROR = C.TOXAV_FRIEND_CALL_STATE_ERROR
	FRIEND_CALL_STATE_FINISHED = C.TOXAV_FRIEND_CALL_STATE_FINISHED
	FRIEND_CALL_STATE_SENDING_A = C.TOXAV_FRIEND_CALL_STATE_SENDING_A
	FRIEND_CALL_STATE_SENDING_V = C.TOXAV_FRIEND_CALL_STATE_SENDING_V
	FRIEND_CALL_STATE_ACCEPTING_A = C.TOXAV_FRIEND_CALL_STATE_ACCEPTING_A
	FRIEND_CALL_STATE_ACCEPTING_V = C.TOXAV_FRIEND_CALL_STATE_ACCEPTING_V
)

// call control
type Call_control = C.TOXAV_CALL_CONTROL
const (
	CALL_CONTROL_RESUME = C.TOXAV_CALL_CONTROL_RESUME
	CALL_CONTROL_PAUSE = C.TOXAV_CALL_CONTROL_PAUSE
	CALL_CONTROL_CANCEL = C.TOXAV_CALL_CONTROL_CANCEL
	CALL_CONTROL_MUTE_AUDIO = C.TOXAV_CALL_CONTROL_MUTE_AUDIO
	CALL_CONTROL_UNMUTE_AUDIO = C.TOXAV_CALL_CONTROL_UNMUTE_AUDIO
	CALL_CONTROL_HIDE_VIDEO = C.TOXAV_CALL_CONTROL_HIDE_VIDEO
	CALL_CONTROL_SHOW_VIDEO = C.TOXAV_CALL_CONTROL_SHOW_VIDEO
)

type Callback_call = func(m *AV, fid uint32, audio bool, video bool)
type Callback_call_state = func(m *AV, fid uint32, state uint32)
type Callback_bit_rate_status = func(m *AV, fid uint32, audio uint32, video uint32)
type Callback_audio_receive_frame = func(m *AV, fid uint32, pcm []int16, sample_count uint32, channels uint8, sampling_rate uint32)
type Callback_video_receive_frame = func(m *AV, fid uint32, width uint16, height uint16, y []byte, u []byte, v []byte, ystride int32, ustride int32, vstride int32)

// main struct
type AV struct {
	// private
	av *C.ToxAV
	mtx sync.Mutex

	// private callback wrapper
	callback_call Callback_call
	callback_call_state Callback_call_state
	callback_bit_rate_status Callback_bit_rate_status
	callback_audio_receive_frame Callback_audio_receive_frame
	callback_video_receive_frame Callback_video_receive_frame
}

var (
	avMap sync.Map
	loopMap sync.Map

	ErrAVNewMultiple = errors.New("attempted to create a second session for the same Tox instance.")
	ErrAVSync = errors.New("synchronization error occurred.")
	ErrAVInvalidBitRate = errors.New("audio or video bit rate is invalid.")
	ErrAVFriendNotInCall = errors.New("this client is currently not in a call with the friend.")

	ErrAVCallFriendAlreadyInCall = errors.New("attempted to call a friend while already in an audio or video call with them.")

  ErrAVAnswerCodecInitialization = errors.New("failed to initialize codecs for call session.")
	ErrAVAnswerFriendNotCalling = errors.New("the friend was valid, but they are not currently trying to initiate a call.")

	ErrAVCallControlInvalidTransition = errors.New("happens if user tried to pause an already paused call or if trying to resume a call that is not paused.")

	ErrAVBitRateSetInvalidAudioBitRate = errors.New("audio bit rate is invalid.")
	ErrAVBitRateSetInvalidVideoBitRate = errors.New("video bit rate is invalid.")

	ErrAVSendFrameNull = errors.New("in case of video, one of Y, U, or V was NULL.")
	ErrAVSendFramePayloadTypeDisabled = errors.New("either friend turned off audio or video receiving or we turned off sending for the said payload.")
	ErrAVSendFrameRtpFailed = errors.New("failed to push frame through rtp interface.")
)
// ================================

// ========== utils ================
func uint8_bytes(arr *C.uint8_t, length C.size_t) []byte {
	hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(arr)), Len: int(length), Cap: int(length)}
	return *(*[]byte)(unsafe.Pointer(&hdr))
}

func uint8_str(arr *C.uint8_t, length C.size_t) string {
	hdr := reflect.StringHeader{Data: uintptr(unsafe.Pointer(arr)), Len: int(length)}
	return *(*string)(unsafe.Pointer(&hdr))
}

func str_bytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	hdr := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
	return *(*[]byte)(unsafe.Pointer(&hdr))
}

func bytes_str(s []byte) string {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr := reflect.StringHeader{Data: sh.Data, Len: sh.Len}
	return *(*string)(unsafe.Pointer(&hdr))
}
// =================================

// ========== callback wrapper =====
func (m *AV) Set_callback(name string, f interface{}) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	switch name {
	case "callback_call":
		if cb,ok := f.(Callback_call); ok {
			m.callback_call = cb
			C.callback_call(m.av)
		} else {
			m.callback_call = nil
			C.callback_call(nil)
		}
	case "callback_call_state":
		if cb,ok := f.(Callback_call_state); ok {
			m.callback_call_state = cb
			C.callback_call_state(m.av)
		} else {
			m.callback_call_state = nil
			C.callback_call_state(nil)
		}
	case "callback_bit_rate_status":
		if cb,ok := f.(Callback_bit_rate_status); ok {
			m.callback_bit_rate_status = cb
			C.callback_bit_rate_status(m.av)
		} else {
			m.callback_bit_rate_status = nil
			C.callback_bit_rate_status(nil)
		}
	case "callback_audio_receive_frame":
		if cb,ok := f.(Callback_audio_receive_frame); ok {
			m.callback_audio_receive_frame = cb
			C.callback_audio_receive_frame(m.av)
		} else {
			m.callback_audio_receive_frame = nil
			C.callback_audio_receive_frame(nil)
		}
	case "callback_video_receive_frame":
		if cb,ok := f.(Callback_video_receive_frame); ok {
			m.callback_video_receive_frame = cb
			C.callback_video_receive_frame(m.av)
		} else {
			m.callback_video_receive_frame = nil
			C.callback_video_receive_frame(nil)
		}
	}
}

// call setup
//export cb_call
func cb_call(m *C.ToxAV, fid C.uint32_t, audio C.bool, video C.bool, null unsafe.Pointer) {
	n,_ := avMap.Load(m)
	v,e := n.(*AV)
	if e {
		v.callback_call(v, uint32(fid), bool(audio), bool(video))
	}
}

// call state graph
//export cb_call_state
func cb_call_state(m *C.ToxAV, fid C.uint32_t, state C.uint32_t, null unsafe.Pointer) {
	n,_ := avMap.Load(m)
	v,e := n.(*AV)
	if e {
		v.callback_call_state(v, uint32(fid), uint32(state))
	}
}

// controlling bit rates
//export cb_bit_rate_status
func cb_bit_rate_status(m *C.ToxAV, fid C.uint32_t, audio C.uint32_t, video C.uint32_t, null unsafe.Pointer) {
	n,_ := avMap.Load(m)
	v,e := n.(*AV)
	if e {
		v.callback_bit_rate_status(v, uint32(fid), uint32(audio), uint32(video))
	}
}

// receiving
//export cb_audio_receive_frame
func cb_audio_receive_frame(m *C.ToxAV, fid C.uint32_t, pcm *C.int16_t, sample_count C.size_t, channels C.uint8_t, sampling_rate C.uint32_t, null unsafe.Pointer) {
	hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(pcm)), Len: int(uint32(sample_count)*uint32(channels)), Cap: int(uint32(sample_count)*uint32(channels))}

	n,_ := avMap.Load(m)
	v,e := n.(*AV)
	if e {
		v.callback_audio_receive_frame(v, uint32(fid), *(*[]int16)(unsafe.Pointer(&hdr)), uint32(sample_count), uint8(channels), uint32(sampling_rate))
	}
}

func max(a C.uint16_t, b C.int32_t) uint32 {
	if uint32(a) > uint32(b) {
		return uint32(a)
	} else {
		return uint32(b)
	}
}

//export cb_video_receive_frame
func cb_video_receive_frame(m *C.ToxAV, fid C.uint32_t, width C.uint16_t, height C.uint16_t, y *C.uint8_t, u *C.uint8_t, v *C.uint8_t, ys C.int32_t, us C.int32_t, vs C.int32_t, null unsafe.Pointer) {
	_y := C.size_t(max(width, ys))
	_u := C.size_t(max(width/2, us))
	_v := C.size_t(max(width/2, vs))
	n,_ := avMap.Load(m)
	g,e := n.(*AV)
	if e {
		g.callback_video_receive_frame(g, uint32(fid), uint16(width), uint16(height), uint8_bytes(y, _y), uint8_bytes(u, _u), uint8_bytes(v, _v), int32(ys), int32(us), int32(vs))
	}
}
// ================================

// =========== methods ============
// gtoav specific
func (m *AV) Lock() {
	m.mtx.Lock()
}

func (m *AV) Unlock() {
	m.mtx.Unlock()
}

// creation and destruction
func NewAV(tox *Tox) (*AV, error) {
	var err C.TOXAV_ERR_NEW = C.TOXAV_ERR_NEW_OK
	r := C.toxav_new((*C.struct_Tox)(tox.Ctox()), &err)

	switch err {
	case C.TOXAV_ERR_NEW_OK:
		m := &AV{av: r}
		avMap.Store(r, m)
		return m, nil
	case C.TOXAV_ERR_NEW_NULL:
		return nil, ErrNull
	case C.TOXAV_ERR_NEW_MALLOC:
		return nil, ErrMalloc
	case C.TOXAV_ERR_NEW_MULTIPLE:
		return nil, ErrAVNewMultiple
	default:
		return nil, ErrInternal
	}
}

func (m *AV) Kill() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	C.toxav_kill(m.av)
	avMap.Delete(m.av)
}

func (m *AV) Cav() unsafe.Pointer {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return unsafe.Pointer(m.av)
}

// event loop
func (m *AV) Iteration_interval() time.Duration {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return time.Duration(C.toxav_iteration_interval(m.av))*time.Millisecond
}

func (m *AV) Iterate() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	C.toxav_iterate(m.av)
}

func (m *AV) IterateLoop(cb func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		loopMap.Delete(m.av)
		cancel()
		cb()
	}()
	loopMap.Store(m.av, &cancel)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			m.Iterate()
			time.Sleep(m.Iteration_interval())
		}
	}
}

func (m *AV) StopIterateLoop() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	n,_ := loopMap.Load(m.av)
	if v,ok := n.(*context.CancelFunc); ok {
		(*v)()
		loopMap.Delete(m.av)
	}
}

// call setup
func (m *AV) Call(fid uint32, audio_bit_rate uint32, video_bit_rate uint32) error {
	var err C.TOXAV_ERR_CALL = C.TOXAV_ERR_CALL_OK

	C.toxav_call(m.av,
		C.uint32_t(fid),
		C.uint32_t(audio_bit_rate),
		C.uint32_t(video_bit_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_CALL_OK:
		return nil
	case C.TOXAV_ERR_CALL_MALLOC:
		return ErrMalloc
	case C.TOXAV_ERR_CALL_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_CALL_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL:
		return ErrAVCallFriendAlreadyInCall
	case C.TOXAV_ERR_CALL_INVALID_BIT_RATE:
		return ErrAVInvalidBitRate
	default:
		return ErrInternal
	}
}

func (m *AV) Answer(fid uint32, audio_bit_rate uint32, video_bit_rate uint32) error {
	var err C.TOXAV_ERR_ANSWER = C.TOXAV_ERR_ANSWER_OK

	C.toxav_answer(m.av,
		C.uint32_t(fid),
		C.uint32_t(audio_bit_rate),
		C.uint32_t(video_bit_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_ANSWER_OK:
		return nil
	case C.TOXAV_ERR_ANSWER_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_ANSWER_CODEC_INITIALIZATION:
		return ErrAVAnswerCodecInitialization
	case C.TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING:
		return errors.New("the friend was valid, but they are not currently trying to initiate a call.")
	case C.TOXAV_ERR_ANSWER_INVALID_BIT_RATE:
		return ErrAVInvalidBitRate
	default:
		return ErrInternal
	}
}

// call control
func (m *AV) Call_control(fid uint32, control Call_control) error {
	var err C.TOXAV_ERR_CALL_CONTROL = C.TOXAV_ERR_CALL_CONTROL_OK

	C.toxav_call_control(m.av,
		C.uint32_t(fid),
		control,
		&err)

	switch err {
	case C.TOXAV_ERR_CALL_CONTROL_OK:
		return nil
	case C.TOXAV_ERR_BIT_RATE_SET_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL:
		return ErrAVFriendNotInCall
	case C.TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION:
		return ErrAVCallControlInvalidTransition
	default:
		return ErrInternal
	}
}

// controlling bit rates
func (m *AV) Bit_rate_set(fid uint32, arate uint32, vrate uint32) error {
	var err C.TOXAV_ERR_BIT_RATE_SET = C.TOXAV_ERR_BIT_RATE_SET_OK

	// https://github.com/TokTok/c-toxcore/issues/572
	C.toxav_bit_rate_set(m.av,
		C.uint32_t(fid),
		C.int32_t(arate),
		C.int32_t(vrate),
		&err)

	switch err {
	case C.TOXAV_ERR_BIT_RATE_SET_OK:
		return nil
	case C.TOXAV_ERR_BIT_RATE_SET_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_BIT_RATE_SET_INVALID_AUDIO_BIT_RATE:
		return ErrAVBitRateSetInvalidAudioBitRate
	case C.TOXAV_ERR_BIT_RATE_SET_INVALID_VIDEO_BIT_RATE:
		return ErrAVBitRateSetInvalidVideoBitRate
	case C.TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL:
		return ErrAVFriendNotInCall
	default:
		return ErrInternal
	}
}

// sending
func (m *AV) Audio_send_frame(fid uint32, pcm []int16, sample_count uint32, channels uint8, sampling_rate uint32) error {
	var err C.TOXAV_ERR_SEND_FRAME = C.TOXAV_ERR_SEND_FRAME_OK

	C.toxav_audio_send_frame(m.av,
		C.uint32_t(fid),
		(*C.int16_t)(&pcm[0]),
		C.size_t(sample_count),
		C.uint8_t(channels),
		C.uint32_t(sampling_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_SEND_FRAME_OK:
		return nil
	case C.TOXAV_ERR_SEND_FRAME_NULL:
		return ErrAVSendFrameNull
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL:
		return ErrAVFriendNotInCall
	case C.TOXAV_ERR_SEND_FRAME_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_SEND_FRAME_INVALID:
		return ErrNull
	case C.TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED:
		return ErrAVSendFramePayloadTypeDisabled
	case C.TOXAV_ERR_SEND_FRAME_RTP_FAILED:
		return ErrAVSendFrameRtpFailed
	default:
		return ErrInternal
	}
}

func (m *AV) Video_send_frame(fid uint32, width uint16, height uint16, y []byte, u []byte, v []byte) error {
	var err C.TOXAV_ERR_SEND_FRAME = C.TOXAV_ERR_SEND_FRAME_OK

	C.toxav_video_send_frame(m.av,
		C.uint32_t(fid),
		C.uint16_t(width),
		C.uint16_t(height),
		(*C.uint8_t)(&y[0]),
		(*C.uint8_t)(&u[0]),
		(*C.uint8_t)(&v[0]),
		&err)

	switch err {
	case C.TOXAV_ERR_SEND_FRAME_OK:
		return nil
	case C.TOXAV_ERR_SEND_FRAME_NULL:
		return ErrAVSendFrameNull
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL:
		return ErrAVFriendNotInCall
	case C.TOXAV_ERR_SEND_FRAME_SYNC:
		return ErrAVSync
	case C.TOXAV_ERR_SEND_FRAME_INVALID:
		return ErrNull
	case C.TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED:
		return ErrAVSendFramePayloadTypeDisabled
	case C.TOXAV_ERR_SEND_FRAME_RTP_FAILED:
		return ErrAVSendFrameRtpFailed
	default:
		return ErrInternal
	}
}
// ================================
