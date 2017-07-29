package gtox

/*
#include <tox/toxav.h>

#define CBB(x) \
static void set_##x(ToxAV* av, void* ud) { \
	toxav_callback_##x(av, (toxav_##x##_cb*)&cb_##x, ud); \
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
type Call_control_t C.TOXAV_CALL_CONTROL
const (
	CALL_CONTROL_RESUME = C.TOXAV_CALL_CONTROL_RESUME
	CALL_CONTROL_PAUSE = C.TOXAV_CALL_CONTROL_PAUSE
	CALL_CONTROL_CANCEL = C.TOXAV_CALL_CONTROL_CANCEL
	CALL_CONTROL_MUTE_AUDIO = C.TOXAV_CALL_CONTROL_MUTE_AUDIO
	CALL_CONTROL_UNMUTE_AUDIO = C.TOXAV_CALL_CONTROL_UNMUTE_AUDIO
	CALL_CONTROL_HIDE_VIDEO = C.TOXAV_CALL_CONTROL_HIDE_VIDEO
	CALL_CONTROL_SHOW_VIDEO = C.TOXAV_CALL_CONTROL_SHOW_VIDEO
)

type Call func(m *AV, fid uint32, audio bool, video bool)
type Call_state func(m *AV, fid uint32, state uint32)
type Bit_rate_status func(m *AV, fid uint32, audio uint32, video uint32)
type Audio_receive_frame func(m *AV, fid uint32, pcm []int16, sample_count uint32, channels uint8, sampling_rate uint32)
type Video_receive_frame func(m *AV, fid uint32, width uint16, height uint16, y []byte, u []byte, v []byte, ystride int32, ustride int32, vstride int32)

// main struct
type AV struct {
	// private
	av *C.ToxAV

	// private callback wrapper
	call Call
	call_state Call_state
	bit_rate_status Bit_rate_status
	audio_receive_frame Audio_receive_frame
	video_receive_frame Video_receive_frame
}
// ================================

// ========== callback wrapper =====
// call setup
//export cb_call
func cb_call(m *C.ToxAV, fid C.uint32_t, audio C.bool, video C.bool, av unsafe.Pointer) {
	(*AV)(av).call((*AV)(av), uint32(fid), bool(audio), bool(video))
}

// call state graph
//export cb_call_state
func cb_call_state(m *C.ToxAV, fid C.uint32_t, state C.uint32_t, av unsafe.Pointer) {
	(*AV)(av).call_state((*AV)(av), uint32(fid), uint32(state))
}

// controlling bit rates
//export cb_bit_rate_status
func cb_bit_rate_status(m *C.ToxAV, fid C.uint32_t, audio C.uint32_t, video C.uint32_t, av unsafe.Pointer) {
	(*AV)(av).bit_rate_status((*AV)(av), uint32(fid), uint32(audio), uint32(video))
}

// receiving
//export cb_audio_receive_frame
func cb_audio_receive_frame(m *C.ToxAV, fid C.uint32_t, pcm *C.int16_t, sample_count C.size_t, channels C.uint8_t, sampling_rate C.uint32_t, av unsafe.Pointer) {
	var _pcm []int16
	pcm_h := (*reflect.SliceHeader)((unsafe.Pointer(&_pcm)))
	pcm_h.Cap = int(uint32(sample_count)*uint32(channels))
	pcm_h.Len = int(uint32(sample_count)*uint32(channels))
	pcm_h.Data = uintptr(unsafe.Pointer(pcm))
	(*AV)(av).audio_receive_frame((*AV)(av), uint32(fid), _pcm, uint32(sample_count), uint8(channels), uint32(sampling_rate))
}

func max(a C.uint16_t, b C.int32_t) uint32 {
	if uint32(a) > uint32(b) {
		return uint32(a)
	} else {
		return uint32(b)
	}
}

//export cb_video_receive_frame
func cb_video_receive_frame(m *C.ToxAV, fid C.uint32_t, width C.uint16_t, height C.uint16_t, y *C.uint8_t, u *C.uint8_t, v *C.uint8_t, ys C.int32_t, us C.int32_t, vs C.int32_t, av unsafe.Pointer) {
	var _y = max(width, ys)
	var _u = max(width/2, us)
	var _v = max(width/2, vs)
	(*AV)(av).video_receive_frame((*AV)(av), uint32(fid), uint16(width), uint16(height), C.GoBytes(unsafe.Pointer(y), C.int(_y)), C.GoBytes(unsafe.Pointer(u), C.int(_u)), C.GoBytes(unsafe.Pointer(v), C.int(_v)), int32(ys), int32(us), int32(vs))
}
// ================================

// =========== methods ============
// creation and destruction
func (this *AV) New(tox *Tox) error {
	var err C.TOXAV_ERR_NEW = C.TOXAV_ERR_NEW_OK

	this.av = C.toxav_new(tox.tox, &err)

	switch err {
	case C.TOXAV_ERR_NEW_OK:
		return nil
	case C.TOXAV_ERR_NEW_NULL:
		return errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOXAV_ERR_NEW_MALLOC:
		return errors.New("memory allocation failure while trying to allocate structures required for the A/V session.")
	case C.TOXAV_ERR_NEW_MULTIPLE:
		return errors.New("attempted to create a second session for the same Tox instance.")
	default:
		return errors.New("internal error.")
	}
}

func (this *AV) Del() {
	C.toxav_kill(this.av)
}

func (this *AV) Tox() *Tox {
	return (*Tox)(unsafe.Pointer(C.toxav_get_tox(this.av)))
}

// event loop
func (this *AV) Iteration_interval() time.Time {
	return time.Unix(int64(C.toxav_iteration_interval(this.av)), 0)
}

func (this *AV) Iterate() {
	C.toxav_iterate(this.av)
}

// call setup
func (this *AV) Call(fid uint32, audio_bit_rate uint32, video_bit_rate uint32) (bool, error) {
	var err C.TOXAV_ERR_CALL = C.TOXAV_ERR_CALL_OK

	r := C.toxav_call(this.av,
		C.uint32_t(fid),
		C.uint32_t(audio_bit_rate),
		C.uint32_t(video_bit_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_CALL_OK:
		return bool(r), nil
	case C.TOXAV_ERR_CALL_MALLOC:
		return bool(r), errors.New("a resource allocation error occurred while trying to create the structures required for the call.")
	case C.TOXAV_ERR_CALL_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_CALL_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("the friend was valid, but not currently connected.")
	case C.TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL:
		return bool(r), errors.New("attempted to call a friend while already in an audio or video call with them.")
	case C.TOXAV_ERR_CALL_INVALID_BIT_RATE:
		return bool(r), errors.New("audio or video bit rate is invalid.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *AV) Callback_call(cb Call, ud unsafe.Pointer) {
	this.call = cb
	C.set_call(this.av, ud);
}

func (this *AV) Answer(fid uint32, audio_bit_rate uint32, video_bit_rate uint32) (bool, error) {
	var err C.TOXAV_ERR_ANSWER = C.TOXAV_ERR_ANSWER_OK

	r := C.toxav_answer(this.av,
		C.uint32_t(fid),
		C.uint32_t(audio_bit_rate),
		C.uint32_t(video_bit_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_ANSWER_OK:
		return bool(r), nil
	case C.TOXAV_ERR_ANSWER_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_ANSWER_CODEC_INITIALIZATION:
		return bool(r), errors.New("failed to initialize codecs for call session.")
	case C.TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING:
		return bool(r), errors.New("the friend was valid, but they are not currently trying to initiate a call.")
	case C.TOXAV_ERR_ANSWER_INVALID_BIT_RATE:
		return bool(r), errors.New("audio or video bit rate is invalid.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

// call state graph
func (this *AV) Callback_call_state(cb Call_state, ud unsafe.Pointer) {
	this.call_state = cb
	C.set_call_state(this.av, ud);
}

// call control
func (this *AV) Call_control(fid uint32, control Call_control_t) (bool, error) {
	var err C.TOXAV_ERR_CALL_CONTROL = C.TOXAV_ERR_CALL_CONTROL_OK

	r := C.toxav_call_control(this.av,
		C.uint32_t(fid),
		C.TOXAV_CALL_CONTROL(control),
		&err)

	switch err {
	case C.TOXAV_ERR_CALL_CONTROL_OK:
		return bool(r), nil
	case C.TOXAV_ERR_BIT_RATE_SET_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL:
		return bool(r), errors.New("this client is currently not in a call with the friend.")
	case C.TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION:
		return bool(r), errors.New("happens if user tried to pause an already paused call or if trying to resume a call that is not paused.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

// controlling bit rates
func (this *AV) Bit_rate_set(fid uint32, arate uint32, vrate uint32) (bool, error) {
	var err C.TOXAV_ERR_BIT_RATE_SET = C.TOXAV_ERR_BIT_RATE_SET_OK

	// https://github.com/TokTok/c-toxcore/issues/572
	r := C.toxav_bit_rate_set(this.av,
		C.uint32_t(fid),
		C.int32_t(arate),
		C.int32_t(vrate),
		&err)

	switch err {
	case C.TOXAV_ERR_BIT_RATE_SET_OK:
		return bool(r), nil
	case C.TOXAV_ERR_BIT_RATE_SET_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_BIT_RATE_SET_INVALID_AUDIO_BIT_RATE:
		return bool(r), errors.New("audio bit rate is invalid.")
	case C.TOXAV_ERR_BIT_RATE_SET_INVALID_VIDEO_BIT_RATE:
		return bool(r), errors.New("video bit rate is invalid.")
	case C.TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL:
		return bool(r), errors.New("this client is currently not in a call with the friend.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *AV) Bit_rate_status(cb Bit_rate_status, ud unsafe.Pointer) {
	this.bit_rate_status = cb
	C.set_bit_rate_status(this.av, ud)
}

// sending
func (this *AV) Audio_send_frame(fid uint32, pcm []int16, sample_count uint32, channels uint8, sampling_rate uint32) (bool, error) {
	var err C.TOXAV_ERR_SEND_FRAME = C.TOXAV_ERR_SEND_FRAME_OK

	r := C.toxav_audio_send_frame(this.av,
		C.uint32_t(fid),
		(*C.int16_t)(&pcm[0]),
		C.size_t(sample_count),
		C.uint8_t(channels),
		C.uint32_t(sampling_rate),
		&err)

	switch err {
	case C.TOXAV_ERR_SEND_FRAME_OK:
		return bool(r), nil
	case C.TOXAV_ERR_SEND_FRAME_NULL:
		return bool(r), errors.New("in case of video, one of Y, U, or V was NULL.")
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL:
		return bool(r), errors.New("this client is currently not in a call with the friend.")
	case C.TOXAV_ERR_SEND_FRAME_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_SEND_FRAME_INVALID:
		return bool(r), errors.New("one of the frame parameters was invalid.")
	case C.TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED:
		return bool(r), errors.New("either friend turned off audio or video receiving or we turned off sending for the said payload.")
	case C.TOXAV_ERR_SEND_FRAME_RTP_FAILED:
		return bool(r), errors.New("failed to push frame through rtp interface.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *AV) Video_send_frame(fid uint32, width uint16, height uint16, y []byte, u []byte, v []byte) (bool, error) {
	var err C.TOXAV_ERR_SEND_FRAME = C.TOXAV_ERR_SEND_FRAME_OK

	r := C.toxav_video_send_frame(this.av,
		C.uint32_t(fid),
		C.uint16_t(width),
		C.uint16_t(height),
		(*C.uint8_t)(&y[0]),
		(*C.uint8_t)(&u[0]),
		(*C.uint8_t)(&v[0]),
		&err)

	switch err {
	case C.TOXAV_ERR_SEND_FRAME_OK:
		return bool(r), nil
	case C.TOXAV_ERR_SEND_FRAME_NULL:
		return bool(r), errors.New("in case of video, one of Y, U, or V was NULL.")
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL:
		return bool(r), errors.New("this client is currently not in a call with the friend.")
	case C.TOXAV_ERR_SEND_FRAME_SYNC:
		return bool(r), errors.New("synchronization error occurred.")
	case C.TOXAV_ERR_SEND_FRAME_INVALID:
		return bool(r), errors.New("one of the frame parameters was invalid.")
	case C.TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED:
		return bool(r), errors.New("either friend turned off audio or video receiving or we turned off sending for the said payload.")
	case C.TOXAV_ERR_SEND_FRAME_RTP_FAILED:
		return bool(r), errors.New("failed to push frame through rtp interface.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

// receiving
func (this *AV) Callback_audio_receive_frame(cb Audio_receive_frame, ud unsafe.Pointer) {
	this.audio_receive_frame = cb
	C.set_audio_receive_frame(this.av, ud);
}

func (this *AV) Callback_video_receive_frame(cb Video_receive_frame, ud unsafe.Pointer) {
	this.video_receive_frame = cb
	C.set_video_receive_frame(this.av, ud);
}
// ================================
