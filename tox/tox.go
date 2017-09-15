package gtox

/*
#include <tox/tox.h>

#define CB(x) \
static void callback_##x(Tox* tox) { \
	tox_callback_##x(tox, (tox_##x##_cb*)&cb_##x); \
}

// wrapper cb functions
void cb_self_connection_status(Tox*, TOX_CONNECTION, void*);
void cb_friend_name(Tox*, uint32_t, uint8_t*, size_t, void*);
void cb_friend_status_message(Tox*, uint32_t, uint8_t*, size_t, void*);
void cb_friend_status(Tox*, uint32_t, TOX_USER_STATUS, void*);
void cb_friend_connection_status(Tox*, uint32_t, TOX_CONNECTION, void*);
void cb_friend_typing(Tox*, uint32_t, bool, void*);
void cb_friend_read_receipt(Tox*, uint32_t, uint32_t, void*);
void cb_friend_request(Tox*, uint8_t*, uint8_t*, size_t, void*);
void cb_friend_message(Tox*, uint32_t, TOX_MESSAGE_TYPE, uint8_t*, size_t, void*);
void cb_file_recv_control(Tox*, uint32_t, uint32_t, TOX_FILE_CONTROL, void*);
void cb_file_chunk_request(Tox*, uint32_t, uint32_t, uint64_t, size_t, void*);
void cb_file_recv(Tox*, uint32_t, uint32_t, uint32_t, uint64_t, uint8_t*, size_t, void*);
void cb_file_recv_chunk(Tox*, uint32_t, uint32_t, uint64_t, uint8_t*, size_t, void*);
void cb_conference_invite(Tox*, uint32_t, TOX_CONFERENCE_TYPE, uint8_t*, size_t, void*);
void cb_conference_message(Tox*, uint32_t, uint32_t, TOX_MESSAGE_TYPE, uint8_t*, size_t, void*);
void cb_conference_title(Tox*, uint32_t, uint32_t, uint8_t*, size_t, void*);
void cb_conference_namelist_change(Tox*, uint32_t, uint32_t, TOX_CONFERENCE_STATE_CHANGE, void*);
void cb_friend_lossy_packet(Tox*, uint32_t, uint8_t*, size_t, void*);
void cb_friend_lossless_packet(Tox*, uint32_t, uint8_t*, size_t, void*);

CB(self_connection_status)
CB(friend_name)
CB(friend_status_message)
CB(friend_status)
CB(friend_connection_status)
CB(friend_typing)
CB(friend_read_receipt)
CB(friend_request)
CB(friend_message)
CB(file_recv_control)
CB(file_chunk_request)
CB(file_recv)
CB(file_recv_chunk)
CB(conference_invite)
CB(conference_message)
CB(conference_title)
CB(conference_namelist_change)
CB(friend_lossy_packet)
CB(friend_lossless_packet)
*/
import "C"
import (
	"errors"
	"unsafe"
	"encoding/hex"
	"sync"
	"time"
	"context"
	"reflect"
)

// ======== type and enum ==========
const (
	PUBLIC_KEY_SIZE = C.TOX_PUBLIC_KEY_SIZE
	SECRET_KEY_SIZE = C.TOX_SECRET_KEY_SIZE
	NOSPAM_SIZE = C.TOX_NOSPAM_SIZE
	ADDRESS_SIZE = C.TOX_ADDRESS_SIZE
	MAX_NAME_LENGTH = C.TOX_MAX_NAME_LENGTH
	MAX_STATUS_MESSAGE_LENGTH = C.TOX_MAX_STATUS_MESSAGE_LENGTH
	MAX_FRIEND_REQUEST_LENGTH = C.TOX_MAX_FRIEND_REQUEST_LENGTH
	MAX_MESSAGE_LENGTH = C.TOX_MAX_MESSAGE_LENGTH
	MAX_CUSTOM_PACKET_SIZE = C.TOX_MAX_CUSTOM_PACKET_SIZE
	HASH_LENGTH = C.TOX_HASH_LENGTH
	FILE_ID_LENGTH = C.TOX_FILE_ID_LENGTH
	MAX_FILENAME_LENGTH = C.TOX_MAX_FILENAME_LENGTH
)

type User_status = C.TOX_USER_STATUS
const (
	USER_STATUS_NONE = C.TOX_USER_STATUS_NONE
	USER_STATUS_AWAY = C.TOX_USER_STATUS_AWAY
	USER_STATUS_BUSY = C.TOX_USER_STATUS_BUSY
)
type Msg_type = C.TOX_MESSAGE_TYPE
const (
	MSG_NORMAL = C.TOX_MESSAGE_TYPE_NORMAL
	MSG_ACTION = C.TOX_MESSAGE_TYPE_ACTION
)
type Proxy_type = C.TOX_PROXY_TYPE
const (
	PROXY_TYPE_NONE = C.TOX_PROXY_TYPE_NONE
	PROXY_TYPE_HTTP = C.TOX_PROXY_TYPE_HTTP
	PROXY_TYPE_SOCKS5 = C.TOX_PROXY_TYPE_SOCKS5
)
type Savedata_type = C.TOX_SAVEDATA_TYPE
const (
	SAVEDATA_TYPE_NONE = C.TOX_SAVEDATA_TYPE_NONE
	SAVEDATA_TYPE_TOX_SAVE = C.TOX_SAVEDATA_TYPE_TOX_SAVE
	SAVEDATA_TYPE_SECRET_KEY = C.TOX_SAVEDATA_TYPE_SECRET_KEY
)
type Connection = C.TOX_CONNECTION
const (
	CONNECTION_NONE = C.TOX_CONNECTION_NONE
	CONNECTION_TCP = C.TOX_CONNECTION_TCP
	CONNECTION_UDP = C.TOX_CONNECTION_UDP
)
type File_control = C.TOX_FILE_CONTROL
const (
	FILE_CONTROL_RESUME = C.TOX_FILE_CONTROL_RESUME
	FILE_CONTROL_PAUSE = C.TOX_FILE_CONTROL_PAUSE
	FILE_CONTROL_CANCEL = C.TOX_FILE_CONTROL_CANCEL
)
type Conference_type = C.TOX_CONFERENCE_TYPE
const (
	CONFERENCE_TYPE_TEXT = C.TOX_CONFERENCE_TYPE_TEXT
	CONFERENCE_TYPE_AV = C.TOX_CONFERENCE_TYPE_AV
)
type Conference_state_change = C.TOX_CONFERENCE_STATE_CHANGE
const (
	CONFERENCE_STATE_CHANGE_PEER_JOIN = C.TOX_CONFERENCE_STATE_CHANGE_PEER_JOIN
	CONFERENCE_STATE_CHANGE_PEER_EXIT = C.TOX_CONFERENCE_STATE_CHANGE_PEER_EXIT
	CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE = C.TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE
)

type Callback_self_connection_status = func(m *Tox, status Connection)
type Callback_friend_name = func(m *Tox, fid uint32, name string)
type Callback_friend_status_message = func(m *Tox, fid uint32, msg string)
type Callback_friend_status = func(m *Tox, fid uint32, status User_status)
type Callback_friend_connection_status = func(m *Tox, fid uint32, status Connection)
type Callback_friend_typing = func(m *Tox, fid uint32, is_typing bool)
type Callback_friend_read_receipt = func(m *Tox, fid uint32, mid uint32)
type Callback_friend_request = func(m *Tox, pubkey string, message string)
type Callback_friend_message = func(m *Tox, fid uint32, mtype Msg_type, message string)
type Callback_file_recv_control = func(m *Tox, fid uint32, did uint32, control File_control)
type Callback_file_chunk_request = func(m *Tox, fid uint32, did uint32, pos uint64, length uint32)
type Callback_file_recv = func(m *Tox, fid uint32, did uint32, kind uint32, file_size uint64, filename string)
type Callback_file_recv_chunk = func(m *Tox, fid uint32, did uint32, pos uint64, data []byte)
type Callback_conference_invite = func(m *Tox, fid uint32, t Conference_type, cookie []byte)
type Callback_conference_message = func(m *Tox, gid uint32, pid uint32, t Msg_type, message string)
type Callback_conference_title = func(m *Tox, gid uint32, pid uint32, title string)
type Callback_conference_namelist_change = func(m *Tox, gid uint32, pid uint32, change Conference_state_change)
type Callback_friend_lossy_packet = func(m *Tox, fid uint32, data []byte)
type Callback_friend_lossless_packet = func(m *Tox, fid uint32, data []byte)

type Tox_options struct {
	// public
	Ipv6_enabled bool
	Udp_enabled bool
	Local_discovery_enabled bool
	Proxy_type Proxy_type
	Proxy_host string
	Proxy_port uint16
	Start_port uint16
	End_port uint16
	Tcp_port uint16
	Hole_punching_enabled bool
	Savedata_type Savedata_type
	Savedata_data []byte
	Savedata_length uint32

	// private
	opt *C.struct_Tox_Options
	mtx sync.Mutex
}

// main struct
type Tox struct {
	// private
	tox *C.struct_Tox
	mtx sync.Mutex

	callback_self_connection_status Callback_self_connection_status
	callback_friend_name Callback_friend_name
	callback_friend_status_message Callback_friend_status_message
	callback_friend_status Callback_friend_status
	callback_friend_connection_status Callback_friend_connection_status
	callback_friend_typing Callback_friend_typing
	callback_friend_read_receipt Callback_friend_read_receipt
	callback_friend_request Callback_friend_request
	callback_friend_message Callback_friend_message
	callback_file_recv_control Callback_file_recv_control
	callback_file_chunk_request Callback_file_chunk_request
	callback_file_recv Callback_file_recv
	callback_file_recv_chunk Callback_file_recv_chunk
	callback_conference_invite Callback_conference_invite
	callback_conference_message Callback_conference_message
	callback_conference_title Callback_conference_title
	callback_conference_namelist_change Callback_conference_namelist_change
	callback_friend_lossy_packet Callback_friend_lossy_packet
	callback_friend_lossless_packet Callback_friend_lossless_packet
}

var (
	toxMap sync.Map
	loopMap sync.Map

	ErrInternal = errors.New("internal error.")
	ErrNull = errors.New("one of the arguments to the function was NULL when it was not expected.")
	ErrMalloc = errors.New("the function failed to allocate enough memory for the object.")
	ErrFriendNotFound = errors.New("the friend_number did not designate a valid friend.")
	ErrFriendNotConnected = errors.New("this client is currently not connected to the friend.")
	ErrFileNotFound = errors.New("no file transfer with the given file number was found for the given friend.")
	ErrPacketQueueFull = errors.New("packet queue is full.")
	ErrConferenceNotFound = errors.New("conference number passed did not designate a valid conference.")
	ErrConferenceInit = errors.New("conference instance failed to initialize.")
	ErrConferenceNoConnection = errors.New("client is not connected to the conference")

	ErrNewPortAlloc = errors.New("the function was unable to bind to a port.")
	ErrNewProxyBadType = errors.New("proxy_type was invalid.")
	ErrNewProxyBadHost = errors.New("proxy_type was valid but the proxy_host passed had an invalid format or was NULL.")
	ErrNewProxyBadPort = errors.New("proxy_type was valid but the proxy_port was invalid.")
	ErrNewProxyNotFound = errors.New("the proxy address passed could not be resolved.")
	ErrNewLoadEncrypted = errors.New("the byte array to be loaded contained an encrypted save.")
	ErrNewLoadBadFormat = errors.New("the data format was invalid.")

	ErrBootstrapBadHost = errors.New("the address could not be resolved to an IP address, or the IP address passed was invalid.")
	ErrBootstrapBadPort = errors.New("the port passed was invalid. The valid port range is (1, 65535).")

	ErrSetInfoTooLong = errors.New("information length exceeded maximum permissible size.")

	ErrFriendAddTooLong = errors.New("the length of the friend request message exceeded TOX_MAX_FRIEND_REQUEST_LENGTH.")
	ErrFriendAddNoMessage = errors.New("the friend request message was empty.")
	ErrFriendAddOwnKey = errors.New("the friend address belongs to the sending client.")
	ErrFriendAddAlreadySent = errors.New("a friend request has already been sent, or the address belongs to a friend that is already on the friend list.")
	ErrFriendAddBadChecksum = errors.New("the friend address checksum failed.")
	ErrFriendAddSetNewNospam = errors.New("the friend was already there, but the nospam value was different.")

	ErrFriendDeleteFriendNotFound = errors.New("there was no friend with the given friend number. No friends were deleted.")

	ErrFriendByPublicKeyNotFound = errors.New("no friend with the given Public Key exists on the friend list.")

	ErrFriendQueryNull = errors.New("the pointer parameter for storing the query result was nil.")

	ErrFriendSendMessageSendQ = errors.New("an allocation error occurred while increasing the send queue size.")
	ErrFriendSendMessageTooLong = errors.New("message length exceeded MAX_MESSAGE_LENGTH.")
	ErrFriendSendMessageEmpty = errors.New("attempted to send a zero-length message.")

	ErrFileControlNotPaused = errors.New("a RESUME control was sent, but the file transfer is running normally.")
	ErrFileControlDenied = errors.New("a RESUME control was sent, but the file transfer was paused by the other party.")
	ErrFileControlAlreadyPaused = errors.New("a PAUSE control was sent, but the file transfer was already paused.")

	ErrFileSeekDenied = errors.New("file was not in a state where it could be seeked.")
	ErrFileSeekInvalidPosition = errors.New("seek position was invalid.")

	ErrFileSendNameTooLong = errors.New("filename length exceeded MAX_FILENAME_LENGTH bytes.")
	ErrFileSendTooMany = errors.New("too many ongoing transfers.")

	ErrFileSendChunkNull = errors.New("the length parameter was non-zero, but data was NULL.")
	ErrFileSendChunkNotTransferring = errors.New("file transfer was found but isn't in a transferring state.")
	ErrFileSendChunkInvalidLength = errors.New("attempted to send more or less data than requested.")
	ErrFileSendChunkWrongPosition = errors.New("position parameter was wrong.")

	ErrConferenceInviteFailSend = errors.New("invite packet failed to send.")

	ErrConferencePeerQueryPeerNotFound = errors.New("The peer number passed did not designate a valid peer.")

	ErrConferenceJoinInvalidLength = errors.New("cookie passed has an invalid length.")
	ErrConferenceJoinWrongType = errors.New("conference is not the expected type. This indicates an invalid cookie.")
	ErrConferenceJoinDuplicate = errors.New("already in this conference.")
	ErrConferenceJoinFailSend = errors.New("join packet failed to send.")

	ErrConferenceSendMessageTooLong = errors.New("message is too long")
	ErrConferenceSendMessageFailSend = errors.New("message packet failed to send.")

	ErrConferenceTitleInvalidLength = errors.New("title is too long or empty.")
	ErrConferenceTitleFailSend = errors.New("title packet failed to send.")

	ErrFriendCustomPacketInvalid = errors.New("the first byte of data was not in the specified range for the packet type.")
	ErrFriendCustomPacketEmpty = errors.New("attempted to send an empty packet.")
	ErrFriendCustomPacketTooLong = errors.New("packet data length exceeded MAX_CUSTOM_PACKET_SIZE.")

	ErrGetPortNotBound = errors.New("the instance was not bound to any port.")
)
// =================================

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
func (m *Tox) Set_callback(name string, f interface{}) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	switch name {
	case "callback_self_connection_status":
		if cb,ok := f.(Callback_self_connection_status); ok {
			m.callback_self_connection_status = cb
			C.callback_self_connection_status(m.tox)
		} else {
			m.callback_self_connection_status = nil
			C.callback_self_connection_status(nil)
		}
	case "callback_friend_name":
		if cb,ok := f.(Callback_friend_name); ok {
			m.callback_friend_name = cb
			C.callback_friend_name(m.tox)
		} else {
			m.callback_friend_name = nil
			C.callback_friend_name(nil)
		}
	case "callback_friend_status_message":
		if cb,ok := f.(Callback_friend_status_message); ok {
			m.callback_friend_status_message = cb
			C.callback_friend_status_message(m.tox)
		} else {
			m.callback_friend_status_message = nil
			C.callback_friend_status_message(nil)
		}
	case "callback_friend_status":
		if cb,ok := f.(Callback_friend_status); ok {
			m.callback_friend_status = cb
			C.callback_friend_status(m.tox)
		} else {
			m.callback_friend_status = nil
			C.callback_friend_status(nil)
		}
	case "callback_friend_connection_status":
		if cb,ok := f.(Callback_friend_connection_status); ok {
			m.callback_friend_connection_status = cb
			C.callback_friend_connection_status(m.tox)
		} else {
			m.callback_friend_connection_status = nil
			C.callback_friend_connection_status(nil)
		}
	case "callback_friend_typing":
		if cb,ok := f.(Callback_friend_typing); ok {
			m.callback_friend_typing = cb
			C.callback_friend_typing(m.tox)
		} else {
			m.callback_friend_typing = nil
			C.callback_friend_typing(nil)
		}
	case "callback_friend_read_receipt":
		if cb,ok := f.(Callback_friend_read_receipt); ok {
			m.callback_friend_read_receipt = cb
			C.callback_friend_read_receipt(m.tox)
		} else {
			m.callback_friend_read_receipt = nil
			C.callback_friend_read_receipt(nil)
		}
	case "callback_friend_request":
		if cb,ok := f.(Callback_friend_request); ok {
			m.callback_friend_request = cb
			C.callback_friend_request(m.tox)
		} else {
			m.callback_friend_request = nil
			C.callback_friend_request(nil)
		}
	case "callback_friend_message":
		if cb,ok := f.(Callback_friend_message); ok {
			m.callback_friend_message = cb
			C.callback_friend_message(m.tox)
		} else {
			m.callback_friend_message = nil
			C.callback_friend_message(nil)
		}
	case "callback_file_recv_control":
		if cb,ok := f.(Callback_file_recv_control); ok {
			m.callback_file_recv_control = cb
			C.callback_file_recv_control(m.tox)
		} else {
			m.callback_file_recv_control = nil
			C.callback_file_recv_control(nil)
		}
	case "callback_file_chunk_request":
		if cb,ok := f.(Callback_file_chunk_request); ok {
			m.callback_file_chunk_request = cb
			C.callback_file_chunk_request(m.tox)
		} else {
			m.callback_file_chunk_request = nil
			C.callback_file_chunk_request(nil)
		}
	case "callback_file_recv":
		if cb,ok := f.(Callback_file_recv); ok {
			m.callback_file_recv = cb
			C.callback_file_recv(m.tox)
		} else {
			m.callback_file_recv = nil
			C.callback_file_recv(nil)
		}
	case "callback_file_recv_chunk":
		if cb,ok := f.(Callback_file_recv_chunk); ok {
			m.callback_file_recv_chunk = cb
			C.callback_file_recv_chunk(m.tox)
		} else {
			m.callback_file_recv_chunk = nil
			C.callback_file_recv_chunk(nil)
		}
	case "callback_conference_invite":
		if cb,ok := f.(Callback_conference_invite); ok {
			m.callback_conference_invite = cb
			C.callback_conference_invite(m.tox)
		} else {
			m.callback_conference_invite = nil
			C.callback_conference_invite(nil)
		}
	case "callback_conference_message":
		if cb,ok := f.(Callback_conference_message); ok {
			m.callback_conference_message = cb
			C.callback_conference_message(m.tox)
		} else {
			m.callback_conference_message = nil
			C.callback_conference_message(nil)
		}
	case "callback_conference_title":
		if cb,ok := f.(Callback_conference_title); ok {
			m.callback_conference_title = cb
			C.callback_conference_title(m.tox)
		} else {
			m.callback_conference_title = nil
			C.callback_conference_title(nil)
		}
	case "callback_conference_namelist_change":
		if cb,ok := f.(Callback_conference_namelist_change); ok {
			m.callback_conference_namelist_change = cb
			C.callback_conference_namelist_change(m.tox)
		} else {
			m.callback_conference_namelist_change = nil
			C.callback_conference_namelist_change(nil)
		}
	case "callback_friend_lossy_packet":
		if cb,ok := f.(Callback_friend_lossy_packet); ok {
			m.callback_friend_lossy_packet = cb
			C.callback_friend_lossy_packet(m.tox)
		} else {
			m.callback_friend_lossy_packet = nil
			C.callback_friend_lossy_packet(nil)
		}
	case "callback_friend_lossless_packet":
		if cb,ok := f.(Callback_friend_lossless_packet); ok {
			m.callback_friend_lossless_packet = cb
			C.callback_friend_lossless_packet(m.tox)
		} else {
			m.callback_friend_lossless_packet = nil
			C.callback_friend_lossless_packet(nil)
		}
	}
}

// connection lifecycle and event loop
//export cb_self_connection_status
func cb_self_connection_status(m *C.Tox, status Connection, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_self_connection_status(v, status)
	}
}

// friend list queries
//export cb_friend_name
func cb_friend_name(m *C.Tox, fid C.uint32_t, name *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_name(v, uint32(fid), uint8_str(name, length))
	}
}
// friend-specific state queries
//export cb_friend_status_message
func cb_friend_status_message(m *C.Tox, fid C.uint32_t, message *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_status_message(v, uint32(fid), uint8_str(message, length))
	}
}

//export cb_friend_status
func cb_friend_status(m *C.Tox, fid C.uint32_t, status User_status, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_status(v, uint32(fid), status)
	}
}

//export cb_friend_connection_status
func cb_friend_connection_status(m *C.Tox, fid C.uint32_t, status Connection, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_connection_status(v, uint32(fid), status)
	}
}

//export cb_friend_typing
func cb_friend_typing(m *C.Tox, fid C.uint32_t, is_typing C.bool, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_typing(v, uint32(fid), bool(is_typing))
	}
}

// sending private messages
//export cb_friend_read_receipt
func cb_friend_read_receipt(m *C.Tox, fid C.uint32_t, mid C.uint32_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_read_receipt(v, uint32(fid), uint32(mid))
	}
}

// receiving private messages
//export cb_friend_request
func cb_friend_request(m *C.Tox, pubkey *C.uint8_t, message *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_request(v, hex.EncodeToString(uint8_bytes(pubkey, PUBLIC_KEY_SIZE)), uint8_str(message, length))
	}
}

//export cb_friend_message
func cb_friend_message(m *C.Tox, fid C.uint32_t, mtype Msg_type, message *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_message(v, uint32(fid), mtype, uint8_str(message, length))
	}
}

// file transmission: common
//export cb_file_recv_control
func cb_file_recv_control(m *C.Tox, fid C.uint32_t, did C.uint32_t, control File_control, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_file_recv_control(v, uint32(fid), uint32(did), control)
	}
}

// file transmission: sending
//export cb_file_chunk_request
func cb_file_chunk_request(m *C.Tox, fid C.uint32_t, did C.uint32_t, pos C.uint64_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_file_chunk_request(v, uint32(fid), uint32(did), uint64(pos), uint32(length))
	}
}

// file transmission: receiving
//export cb_file_recv
func cb_file_recv(m *C.Tox, fid C.uint32_t, did C.uint32_t, kind C.uint32_t, file_size C.uint64_t, filename *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_file_recv(v, uint32(fid), uint32(did), uint32(kind), uint64(file_size), uint8_str(filename, length))
	}
}

//export cb_file_recv_chunk
func cb_file_recv_chunk(m *C.Tox, fid C.uint32_t, did C.uint32_t, pos C.uint64_t, data *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_file_recv_chunk(v, uint32(fid), uint32(did), uint64(pos), uint8_bytes(data, length))
	}
}

// conference management
//export cb_conference_invite
func cb_conference_invite(m *C.Tox, fid C.uint32_t, t Conference_type, cookie *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_conference_invite(v, uint32(fid), t, uint8_bytes(cookie, length))
	}
}

//export cb_conference_message
func cb_conference_message(m *C.Tox, gid C.uint32_t, pid C.uint32_t, t Msg_type, message *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_conference_message(v, uint32(gid), uint32(pid), t, uint8_str(message, length))
	}
}

//export cb_conference_title
func cb_conference_title(m *C.Tox, gid C.uint32_t, pid C.uint32_t, title *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_conference_title(v, uint32(gid), uint32(pid), uint8_str(title, length))
	}
}

//export cb_conference_namelist_change
func cb_conference_namelist_change(m *C.Tox, gid C.uint32_t, pid C.uint32_t, change Conference_state_change, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_conference_namelist_change(v, uint32(gid), uint32(pid), change)
	}
}

// low-level custom packet sending and receiving
//export cb_friend_lossy_packet
func cb_friend_lossy_packet(m *C.Tox, fid C.uint32_t, data *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_lossy_packet(v, uint32(fid), uint8_bytes(data, length))
	}
}

//export cb_friend_lossless_packet
func cb_friend_lossless_packet(m *C.Tox, fid C.uint32_t, data *C.uint8_t, length C.size_t, null unsafe.Pointer) {
	n,_ := toxMap.Load(m)
	if v,e := n.(*Tox); e {
		v.callback_friend_lossless_packet(v, uint32(fid), uint8_bytes(data, length))
	}
}
// ================================

// =========== methods ============
// gtox specific
func (m *Tox) Ctox() unsafe.Pointer {
	// prevent return a deleted, invalid pointer
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return unsafe.Pointer(m.tox)
}

func (m *Tox) Lock() {
	m.mtx.Lock()
}

func (m *Tox) Unlock() {
	m.mtx.Unlock()
}

// api version
func (m *Tox) Version_major() uint32 {
	return uint32(C.tox_version_major())
}

func (m *Tox) Version_minor() uint32 {
	return uint32(C.tox_version_minor())
}

func (m *Tox) Version_patch() uint32 {
	return uint32(C.tox_version_patch())
}

func (m *Tox) Version_is_compatible(i uint32, n uint32, p uint32) bool {
	return bool(C.tox_version_is_compatible(C.uint32_t(i),
	C.uint32_t(n),
	C.uint32_t(p)))
}

// startup options
func NewOpt() (*Tox_options, error) {
	var err C.TOX_ERR_OPTIONS_NEW = C.TOX_ERR_OPTIONS_NEW_OK

	options := C.tox_options_new(&err)
	C.tox_options_default(options)

	switch err {
	case C.TOX_ERR_OPTIONS_NEW_OK:
		return &Tox_options{opt: options,
			Ipv6_enabled: bool(C.tox_options_get_ipv6_enabled(options)),
			Udp_enabled: bool(C.tox_options_get_udp_enabled(options)),
			Local_discovery_enabled: bool(C.tox_options_get_local_discovery_enabled(options)),
			Proxy_type: Proxy_type(C.tox_options_get_proxy_type(options)),
			Proxy_host: C.GoString(C.tox_options_get_proxy_host(options)),
			Proxy_port: uint16(C.tox_options_get_proxy_port(options)),
			Start_port: uint16(C.tox_options_get_start_port(options)),
			End_port: uint16(C.tox_options_get_end_port(options)),
			Tcp_port: uint16(C.tox_options_get_tcp_port(options)),
			Hole_punching_enabled: bool(C.tox_options_get_hole_punching_enabled(options)),
			Savedata_type: Savedata_type(C.tox_options_get_savedata_type(options)),
			Savedata_length: uint32(C.tox_options_get_savedata_length(options)),
			Savedata_data: uint8_bytes(C.tox_options_get_savedata_data(options), C.tox_options_get_savedata_length(options))}, nil
	case C.TOX_ERR_OPTIONS_NEW_MALLOC:
		return nil, ErrMalloc
	default:
		return nil, ErrInternal
	}
}

func (m *Tox_options) Del() {
	C.tox_options_free(m.opt)
}

// creation and destruction
func New(opt *Tox_options) (*Tox, error) {
	var err C.TOX_ERR_NEW = C.TOX_ERR_NEW_OK

	C.tox_options_set_ipv6_enabled(opt.opt, C.bool(opt.Ipv6_enabled))
	C.tox_options_set_udp_enabled(opt.opt, C.bool(opt.Udp_enabled))
	C.tox_options_set_local_discovery_enabled(opt.opt, C.bool(opt.Local_discovery_enabled))
	C.tox_options_set_proxy_type(opt.opt, C.TOX_PROXY_TYPE(opt.Proxy_type))
	C.tox_options_set_proxy_host(opt.opt, C.CString(opt.Proxy_host))
	C.tox_options_set_proxy_port(opt.opt, C.uint16_t(opt.Proxy_port))
	C.tox_options_set_start_port(opt.opt, C.uint16_t(opt.Start_port))
	C.tox_options_set_end_port(opt.opt, C.uint16_t(opt.End_port))
	C.tox_options_set_tcp_port(opt.opt, C.uint16_t(opt.Tcp_port))
	C.tox_options_set_hole_punching_enabled(opt.opt, C.bool(opt.Hole_punching_enabled))
	if len(opt.Savedata_data) > 0 {
		C.tox_options_set_savedata_type(opt.opt, opt.Savedata_type)
		C.tox_options_set_savedata_length(opt.opt, C.size_t(opt.Savedata_length))
		C.tox_options_set_savedata_data(opt.opt, (*C.uint8_t)(&opt.Savedata_data[0]), C.size_t(opt.Savedata_length))
	}

	r := C.tox_new(opt.opt, &err)

	switch err {
	case C.TOX_ERR_NEW_OK:
		m := &Tox{tox: r}
		toxMap.Store(r, m)
		return m, nil
	case C.TOX_ERR_NEW_NULL:
		return nil, ErrNull
	case C.TOX_ERR_NEW_MALLOC:
		return nil, ErrMalloc
	case C.TOX_ERR_NEW_PORT_ALLOC:
		return nil, ErrNewPortAlloc
	case C.TOX_ERR_NEW_PROXY_BAD_TYPE:
		return nil, ErrNewProxyBadType
	case C.TOX_ERR_NEW_PROXY_BAD_HOST:
		return nil, ErrNewProxyBadHost
	case C.TOX_ERR_NEW_PROXY_BAD_PORT:
		return nil, ErrNewProxyBadPort
	case C.TOX_ERR_NEW_PROXY_NOT_FOUND:
		return nil, ErrNewProxyNotFound
	case C.TOX_ERR_NEW_LOAD_ENCRYPTED:
		return nil, ErrNewLoadEncrypted
	case C.TOX_ERR_NEW_LOAD_BAD_FORMAT:
		return nil, ErrNewLoadBadFormat
	default:
		return nil, ErrInternal
	}
}

func (m *Tox) Kill() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	C.tox_kill(m.tox)
	toxMap.Delete(m.tox)
}

func (m *Tox) Savedata_size() uint32 {
	return uint32(C.tox_get_savedata_size(m.tox))
}

func (m *Tox) Savedata() []byte {
	size := m.Savedata_size()
	if size == 0 {
		return []byte{}
	}

	data := make([]byte, size)
	C.tox_get_savedata(m.tox, (*C.uint8_t)(&data[0]))
	return data
}

// connection lifecycle and event loop
func (m *Tox) Bootstrap(addr string, port uint16, pkey string) error {
	var err C.TOX_ERR_BOOTSTRAP = C.TOX_ERR_BOOTSTRAP_OK
	pubkey, _ := hex.DecodeString(pkey)

	C.tox_bootstrap(m.tox,
	C.CString(addr),
	C.uint16_t(port),
	(*C.uint8_t)(&pubkey[0]),
	&err)

	switch err {
	case C.TOX_ERR_BOOTSTRAP_OK:
		return nil
	case C.TOX_ERR_BOOTSTRAP_NULL:
		return ErrNull
	case C.TOX_ERR_BOOTSTRAP_BAD_HOST:
		return ErrBootstrapBadHost
	case C.TOX_ERR_BOOTSTRAP_BAD_PORT:
		return ErrBootstrapBadPort
	default:
		return ErrInternal
	}
}

func (m *Tox) Add_tcp_relay(addr string, port uint16, pkey string) error {
	var err C.TOX_ERR_BOOTSTRAP = C.TOX_ERR_BOOTSTRAP_OK
	pubkey, _ := hex.DecodeString(pkey)

	C.tox_add_tcp_relay(m.tox,
	C.CString(addr),
	C.uint16_t(port),
	(*C.uint8_t)(&pubkey[0]),
	&err)

	switch err {
	case C.TOX_ERR_BOOTSTRAP_OK:
		return nil
	case C.TOX_ERR_BOOTSTRAP_NULL:
		return ErrNull
	case C.TOX_ERR_BOOTSTRAP_BAD_HOST:
		return ErrBootstrapBadHost
	case C.TOX_ERR_BOOTSTRAP_BAD_PORT:
		return ErrBootstrapBadPort
	default:
		return ErrInternal
	}
}

func (m *Tox) Self_connection_status() Connection {
	return Connection(C.tox_self_get_connection_status(m.tox))
}

func (m *Tox) Iteration_interval() time.Duration {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return time.Duration(C.tox_iteration_interval(m.tox))*time.Millisecond
}

func (m *Tox) Iterate() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	C.tox_iterate(m.tox, nil)
}

func (m *Tox) IterateLoop(cb func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		loopMap.Delete(m.tox)
		cancel()
		cb()
	}()
	loopMap.Store(m.tox, &cancel)
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

func (m *Tox) StopIterateLoop() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	n,_ := loopMap.Load(m.tox)
	if v,ok := n.(*context.CancelFunc); ok {
		(*v)()
		loopMap.Delete(m.tox)
	}
}

// internal client information
func (m *Tox) Self_address() string {
	addr := make([]byte, ADDRESS_SIZE)
	C.tox_self_get_address(m.tox, (*C.uint8_t)(&addr[0]))
	return hex.EncodeToString(addr)
}

func (m *Tox) Self_set_nospam(nospam uint32) {
	C.tox_self_set_nospam(m.tox, C.uint32_t(nospam))
}

func (m *Tox) Self_nospam() uint32 {
	return uint32(C.tox_self_get_nospam(m.tox))
}

func (m *Tox) Self_public_key() string {
	pubkey := make([]byte, PUBLIC_KEY_SIZE)

	C.tox_self_get_public_key(m.tox,
	(*C.uint8_t)(&pubkey[0]))

	return hex.EncodeToString(pubkey)
}

func (m *Tox) Self_secret_key() string {
	seckey := make([]byte, SECRET_KEY_SIZE)

	C.tox_self_get_secret_key(m.tox,
	(*C.uint8_t)(&seckey[0]))

	return hex.EncodeToString(seckey)
}

// user-visible client info 
func (m *Tox) Self_set_name(name string) error {
	var err C.TOX_ERR_SET_INFO = C.TOX_ERR_SET_INFO_OK
	var _name = []byte(name)

	C.tox_self_set_name(m.tox,
	(*C.uint8_t)(&_name[0]),
	C.size_t(len(_name)),
	&err)

	switch err {
	case C.TOX_ERR_SET_INFO_OK:
		return nil
	case C.TOX_ERR_SET_INFO_NULL:
		return ErrNull
	case C.TOX_ERR_SET_INFO_TOO_LONG:
		return ErrSetInfoTooLong
	default:
		return ErrInternal
	}
}

func (m *Tox) Self_name_size() uint32 {
	return uint32(C.tox_self_get_name_size(m.tox))
}

func (m *Tox) Self_name() string {
	size := m.Self_name_size()
	if size == 0 {
		return string("")
	}
	name := make([]byte, size)
	C.tox_self_get_name(m.tox, (*C.uint8_t)(&name[0]))
	return string(name)
}

func (m *Tox) Self_set_status_message(message string) error {
	var err C.TOX_ERR_SET_INFO = C.TOX_ERR_SET_INFO_OK
	var msg =  []byte(message)

	C.tox_self_set_status_message(m.tox,
	(*C.uint8_t)(&msg[0]),
	C.size_t(len(msg)),
	&err)

	switch err {
	case C.TOX_ERR_SET_INFO_OK:
		return nil
	case C.TOX_ERR_SET_INFO_NULL:
		return ErrNull
	case C.TOX_ERR_SET_INFO_TOO_LONG:
		return ErrSetInfoTooLong
	default:
		return ErrInternal
	}
}

func (m *Tox) Self_status_message_size() uint32 {
	return uint32(C.tox_self_get_status_message_size(m.tox))
}

func (m *Tox) Self_status_message() string {
	size := m.Self_status_message_size()
	if size == 0 {
		return string("")
	}
	status_message := make([]byte, size)
	C.tox_self_get_status_message(m.tox, (*C.uint8_t)(&status_message[0]))
	return string(status_message)
}

func (m *Tox) Self_set_status(st User_status) {
	C.tox_self_set_status(m.tox,
	st)
}

func (m *Tox) Self_status() User_status {
	return User_status(C.tox_self_get_status(m.tox))
}

// friend list management
func (m *Tox) Friend_add(address string, message string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_ADD = C.TOX_ERR_FRIEND_ADD_OK
	var msg = []byte(message)
	addr, _ := hex.DecodeString(address)

	r := C.tox_friend_add(m.tox,
	(*C.uint8_t)(&addr[0]),
	(*C.uint8_t)(&msg[0]),
	C.size_t(len(msg)),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_ADD_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_ADD_NULL:
		return uint32(r), ErrNull
	case C.TOX_ERR_FRIEND_ADD_TOO_LONG:
		return uint32(r), ErrFriendAddTooLong
	case C.TOX_ERR_FRIEND_ADD_NO_MESSAGE:
		return uint32(r), ErrFriendAddNoMessage
	case C.TOX_ERR_FRIEND_ADD_OWN_KEY:
		return uint32(r), ErrFriendAddOwnKey
	case C.TOX_ERR_FRIEND_ADD_ALREADY_SENT:
		return uint32(r), ErrFriendAddAlreadySent
	case C.TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
		return uint32(r), ErrFriendAddBadChecksum
	case C.TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
		return uint32(r), ErrFriendAddSetNewNospam
	case C.TOX_ERR_FRIEND_ADD_MALLOC:
		return uint32(r), ErrMalloc
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Friend_add_norequest(pkey string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_ADD = C.TOX_ERR_FRIEND_ADD_OK
	pubkey, _ := hex.DecodeString(pkey)

	r := C.tox_friend_add_norequest(m.tox,
	(*C.uint8_t)(&pubkey[0]),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_ADD_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_ADD_NULL:
		return uint32(r), ErrNull
	case C.TOX_ERR_FRIEND_ADD_TOO_LONG:
		return uint32(r), ErrFriendAddTooLong
	case C.TOX_ERR_FRIEND_ADD_NO_MESSAGE:
		return uint32(r), ErrFriendAddNoMessage
	case C.TOX_ERR_FRIEND_ADD_OWN_KEY:
		return uint32(r), ErrFriendAddOwnKey
	case C.TOX_ERR_FRIEND_ADD_ALREADY_SENT:
		return uint32(r), ErrFriendAddAlreadySent
	case C.TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
		return uint32(r), ErrFriendAddBadChecksum
	case C.TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
		return uint32(r), ErrFriendAddSetNewNospam
	case C.TOX_ERR_FRIEND_ADD_MALLOC:
		return uint32(r), ErrMalloc
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Friend_delete(fid uint32) error {
	var err C.TOX_ERR_FRIEND_DELETE = C.TOX_ERR_FRIEND_DELETE_OK

	C.tox_friend_delete(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_DELETE_OK:
		return nil
	case C.TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND:
		return ErrFriendDeleteFriendNotFound
	default:
		return ErrInternal
	}
}

// friend list queries
func (m *Tox) Friend_by_public_key(pkey string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_BY_PUBLIC_KEY = C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK
	pubkey, _ := hex.DecodeString(pkey)

	r := C.tox_friend_by_public_key(m.tox,
	(*C.uint8_t)(&pubkey[0]),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL:
		return uint32(r), ErrNull
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND:
		return uint32(r), ErrFriendByPublicKeyNotFound
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Friend_exist(fid uint32) bool {
	return bool(C.tox_friend_exists(m.tox, C.uint32_t(fid)))
}

func (m *Tox) Friend_list_size() uint32 {
	return uint32(C.tox_self_get_friend_list_size(m.tox))
}

func (m *Tox) Friend_list() []uint32 {
	size := m.Friend_list_size()
	if size == 0 {
		return []uint32{}
	}
	list := make([]uint32, size)
	C.tox_self_get_friend_list(m.tox, (*C.uint32_t)(&list[0]))
	return list
}

func (m *Tox) Friend_public_key(fid uint32) (string, error) {
	var err C.TOX_ERR_FRIEND_GET_PUBLIC_KEY = C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK
	key := make([]byte, PUBLIC_KEY_SIZE)

	C.tox_friend_get_public_key(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&key[0]),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK:
		return hex.EncodeToString(key), nil
	case C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND:
		return hex.EncodeToString(key), ErrFriendNotFound
	default:
		return hex.EncodeToString(key), ErrInternal
	}
}

func (m *Tox) Friend_last_online(fid uint32) (time.Time, error) {
	var err C.TOX_ERR_FRIEND_GET_LAST_ONLINE = C.TOX_ERR_FRIEND_GET_LAST_ONLINE_OK

	r := C.tox_friend_get_last_online(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_GET_LAST_ONLINE_OK:
		return time.Unix(int64(r), 0), nil
	case C.TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND:
		return time.Unix(int64(r), 0), ErrFriendNotFound
	default:
		return time.Unix(int64(r), 0), ErrInternal
	}
}

// friend-specific state queries 
func (m *Tox) Friend_name_size(fid uint32) (uint32, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_name_size(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return uint32(r), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return uint32(r), ErrFriendNotFound
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Friend_name(fid uint32) (string ,error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK
	size, e := m.Friend_name_size(fid)
	if e != nil || size == 0 {
		return string(""), e
	}
	name := make([]byte, size)

	C.tox_friend_get_name(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&name[0]),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return string(name), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return string(name), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return string(name), ErrFriendNotFound
	default:
		return string(name), ErrInternal
	}
}

func (m *Tox) Friend_status_message_size(fid uint32) (uint32, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_status_message_size(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return uint32(r), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return uint32(r), ErrFriendNotFound
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Friend_status_message(fid uint32) (string, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK
	size, e := m.Friend_status_message_size(fid)
	if e != nil || size == 0 {
		return string(""), e
	}
	msg := make([]byte, size)

	C.tox_friend_get_status_message(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&msg[0]),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return string(msg), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return string(msg), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return string(msg), ErrFriendNotFound
	default:
		return string(msg), ErrInternal
	}
}

func (m *Tox) Friend_status(fid uint32) (User_status, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_status_message_size(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return User_status(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return User_status(r), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return User_status(r), ErrFriendNotFound
	default:
		return User_status(r), ErrInternal
	}
}

func (m *Tox) Friend_connection_status(fid uint32) (Connection, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_connection_status(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return Connection(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return Connection(r), ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return Connection(r), ErrFriendNotFound
	default:
		return Connection(r), ErrInternal
	}
}

func (m *Tox) Friend_get_typing(fid uint32) error {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	C.tox_friend_get_typing(m.tox,
	C.uint32_t(fid),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return ErrFriendQueryNull
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	default:
		return ErrInternal
	}
}

// send private messages
func (m *Tox) Self_set_typing(fid uint32, typing bool) error {
	var err C.TOX_ERR_SET_TYPING = C.TOX_ERR_SET_TYPING_OK

	C.tox_self_set_typing(m.tox,
	C.uint32_t(fid),
	C.bool(typing),
	&err)

	switch err {
	case C.TOX_ERR_SET_TYPING_OK:
		return nil
	case C.TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	default:
		return ErrInternal
	}
}

func (m *Tox) Friend_send_message(fid uint32, mtype Msg_type, message string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_SEND_MESSAGE = C.TOX_ERR_FRIEND_SEND_MESSAGE_OK
	var msg = []byte(message)

	r := C.tox_friend_send_message(m.tox,
	C.uint32_t(fid),
	mtype,
	(*C.uint8_t)(&msg[0]),
	C.size_t(len(msg)),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_NULL:
		return uint32(r), ErrNull
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND:
		return uint32(r), ErrFriendNotFound
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED:
		return uint32(r), ErrFriendNotConnected
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ:
		return uint32(r), ErrFriendSendMessageSendQ
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG:
		return uint32(r), ErrFriendSendMessageTooLong
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY:
		return uint32(r), ErrFriendSendMessageEmpty
	default:
		return uint32(r), ErrInternal
	}
}

// file transmission: common
func (m *Tox) Hash(data []byte) (bool, [HASH_LENGTH]byte) {
	var hash [HASH_LENGTH]byte

	r := C.tox_hash((*C.uint8_t)(&hash[0]), (*C.uint8_t)(&data[0]), C.size_t(len(data)))

	return bool(r), hash
}

func (m *Tox) File_control(fid uint32, did uint32, control File_control) error {
	var err C.TOX_ERR_FILE_CONTROL = C.TOX_ERR_FILE_CONTROL_OK

	C.tox_file_control(m.tox,
	C.uint32_t(fid),
	C.uint32_t(fid),
	control,
	&err)

	switch err {
	case C.TOX_ERR_FILE_CONTROL_OK:
		return nil
	case C.TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOX_ERR_FILE_CONTROL_NOT_FOUND:
		return ErrFileNotFound
	case C.TOX_ERR_FILE_CONTROL_NOT_PAUSED:
		return ErrFileControlNotPaused
	case C.TOX_ERR_FILE_CONTROL_DENIED:
		return ErrFileControlDenied
	case C.TOX_ERR_FILE_CONTROL_ALREADY_PAUSED:
		return ErrFileControlAlreadyPaused
	case C.TOX_ERR_FILE_CONTROL_SENDQ:
		return ErrPacketQueueFull
	default:
		return ErrInternal
	}
}

func (m *Tox) File_seek(fid uint32, did uint32, pos uint64) error {
	var err C.TOX_ERR_FILE_SEEK = C.TOX_ERR_FILE_SEEK_OK

	C.tox_file_seek(m.tox,
	C.uint32_t(fid),
	C.uint32_t(did),
	C.uint64_t(pos),
	&err)

	switch err {
	case C.TOX_ERR_FILE_SEEK_OK:
		return nil
	case C.TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOX_ERR_FILE_SEEK_NOT_FOUND:
		return ErrFileNotFound
	case C.TOX_ERR_FILE_SEEK_DENIED:
		return ErrFileSeekDenied
	case C.TOX_ERR_FILE_SEEK_INVALID_POSITION:
		return ErrFileSeekInvalidPosition
	case C.TOX_ERR_FILE_SEEK_SENDQ:
		return ErrPacketQueueFull
	default:
		return ErrInternal
	}
}

func (m *Tox) File_file_id(fid uint32, did uint32) ([FILE_ID_LENGTH]byte, error) {
	var err C.TOX_ERR_FILE_GET = C.TOX_ERR_FILE_GET_OK
	var file_id [FILE_ID_LENGTH]byte

	C.tox_file_get_file_id(m.tox,
	C.uint32_t(fid),
	C.uint32_t(did),
	(*C.uint8_t)(&file_id[0]),
	&err)

	switch err {
	case C.TOX_ERR_FILE_GET_OK:
		return file_id, nil
	case C.TOX_ERR_FILE_GET_NULL:
		return file_id, ErrNull
	case C.TOX_ERR_FILE_GET_FRIEND_NOT_FOUND:
		return file_id, ErrFriendNotFound
	case C.TOX_ERR_FILE_GET_NOT_FOUND:
		return file_id, ErrFileNotFound
	default:
		return file_id, ErrInternal
	}
}

// file transmission: sending
func (m *Tox) File_send(fid uint32, kind uint32, size uint64, file_id [FILE_ID_LENGTH]byte, filename string) (uint32, error) {
	var err C.TOX_ERR_FILE_SEND = C.TOX_ERR_FILE_SEND_OK
	var fname = []byte(filename)

	r := C.tox_file_send(m.tox,
	C.uint32_t(fid),
	C.uint32_t(kind),
	C.uint64_t(size),
	(*C.uint8_t)(&file_id[0]),
	(*C.uint8_t)(&fname[0]),
	C.size_t(len(fname)),
	&err)

	switch err {
	case C.TOX_ERR_FILE_SEND_OK:
		return uint32(r), nil
	case C.TOX_ERR_FILE_SEND_NULL:
		return uint32(r), ErrNull
	case C.TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND:
		return uint32(r), ErrFriendNotFound
	case C.TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED:
		return uint32(r), ErrFriendNotConnected
	case C.TOX_ERR_FILE_SEND_NAME_TOO_LONG:
		return uint32(r), ErrFileSendNameTooLong
	case C.TOX_ERR_FILE_SEND_TOO_MANY:
		return uint32(r), ErrFileSendTooMany
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) File_send_chunk(fid uint32, did uint32, pos uint64, data []byte) error {
	var err C.TOX_ERR_FILE_SEND_CHUNK = C.TOX_ERR_FILE_SEND_CHUNK_OK

	C.tox_file_send_chunk(m.tox,
	C.uint32_t(fid),
	C.uint32_t(did),
	C.uint64_t(pos),
	(*C.uint8_t)(&data[0]),
	C.size_t(len(data)),
	&err)

	switch err {
	case C.TOX_ERR_FILE_SEND_CHUNK_OK:
		return nil
	case C.TOX_ERR_FILE_SEND_CHUNK_NULL:
		return ErrFileSendChunkNull
	case C.TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND:
		return ErrFileNotFound
	case C.TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING:
		return ErrFileSendChunkNotTransferring
	case C.TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH:
		return ErrFileSendChunkInvalidLength
	case C.TOX_ERR_FILE_SEND_CHUNK_SENDQ:
		return ErrPacketQueueFull
	case C.TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION:
		return ErrFileSendChunkWrongPosition
	default:
		return ErrInternal
	}
}

// conference management
func (m *Tox) Conference_new() (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_NEW = C.TOX_ERR_CONFERENCE_NEW_OK

	r := C.tox_conference_new(m.tox,
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_NEW_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_NEW_INIT:
		return uint32(r), ErrConferenceInit
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Conference_delete(gid uint32) error {
	var err C.TOX_ERR_CONFERENCE_DELETE = C.TOX_ERR_CONFERENCE_DELETE_OK

	C.tox_conference_delete(m.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_DELETE_OK:
		return nil
	case C.TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND:
		return ErrConferenceNotFound
	default:
		return ErrInternal
	}
}

func (m *Tox) Conference_peer_count(gid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	r := C.tox_conference_peer_count(m.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return uint32(r), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
		return uint32(r), ErrConferencePeerQueryPeerNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
		return uint32(r), ErrConferenceNoConnection
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Conference_peer_name_size(gid uint32, pid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	r := C.tox_conference_peer_get_name_size(m.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return uint32(r), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
		return uint32(r), ErrConferencePeerQueryPeerNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
		return uint32(r), ErrConferenceNoConnection
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Conference_peer_name(gid uint32, pid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK
	var name[MAX_NAME_LENGTH] byte

	C.tox_conference_peer_get_name(m.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	(*C.uint8_t)(&name[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return string(name[:]), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return string(name[:]), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
		return string(name[:]), ErrConferencePeerQueryPeerNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
		return string(name[:]), ErrConferenceNoConnection
	default:
		return string(name[:]), ErrInternal
	}
}

func (m *Tox) Conference_peer_public_key(gid uint32, pid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK
	key := make([]byte, PUBLIC_KEY_SIZE)

	C.tox_conference_peer_get_public_key(m.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	(*C.uint8_t)(&key[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return hex.EncodeToString(key), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return hex.EncodeToString(key), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
		return hex.EncodeToString(key), ErrConferencePeerQueryPeerNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
		return hex.EncodeToString(key), ErrConferenceNoConnection
	default:
		return hex.EncodeToString(key), ErrInternal
	}
}

func (m *Tox) Conference_peer_number_is_ours(gid uint32, pid uint32) error {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	C.tox_conference_peer_number_is_ours(m.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
		return ErrConferencePeerQueryPeerNotFound
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
		return ErrConferenceNoConnection
	default:
		return ErrInternal
	}
}

func (m *Tox) Conference_invite(fid uint32, gid uint32) error {
	var err C.TOX_ERR_CONFERENCE_INVITE = C.TOX_ERR_CONFERENCE_INVITE_OK

	C.tox_conference_invite(m.tox,
	C.uint32_t(fid),
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_INVITE_OK:
		return nil
	case C.TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND:
		return ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return ErrConferenceInviteFailSend
	default:
		return ErrInternal
	}
}

func (m *Tox) Conference_join(fid uint32, cookie []byte) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_JOIN = C.TOX_ERR_CONFERENCE_JOIN_OK

	r := C.tox_conference_join(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&cookie[0]),
	C.size_t(len(cookie)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_JOIN_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH:
		return uint32(r), ErrConferenceJoinInvalidLength
	case C.TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE:
		return uint32(r), ErrConferenceJoinWrongType
	case C.TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND:
		return uint32(r), ErrFriendNotFound
	case C.TOX_ERR_CONFERENCE_JOIN_DUPLICATE:
		return uint32(r), ErrConferenceJoinDuplicate
	case C.TOX_ERR_CONFERENCE_JOIN_INIT_FAIL:
		return uint32(r), ErrConferenceInit
	case C.TOX_ERR_CONFERENCE_JOIN_FAIL_SEND:
		return uint32(r), ErrConferenceJoinFailSend
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Conference_send_message(gid uint32, t Msg_type, message string) error {
	var err C.TOX_ERR_CONFERENCE_SEND_MESSAGE = C.TOX_ERR_CONFERENCE_SEND_MESSAGE_OK
	var msg = []byte(message)

	C.tox_conference_send_message(m.tox,
	C.uint32_t(gid),
	t,
	(*C.uint8_t)(&msg[0]),
	C.size_t(len(msg)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_OK:
		return nil
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND:
		return ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG:
		return ErrConferenceSendMessageTooLong
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION:
		return ErrConferenceNoConnection
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND:
		return ErrConferenceSendMessageFailSend
	default:
		return ErrInternal
	}
}

func (m *Tox) Conference_title_size(gid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK

	r := C.tox_conference_get_title_size(m.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
		return uint32(r), ErrConferenceTitleInvalidLength
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return uint32(r), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return uint32(r), ErrConferenceTitleFailSend
	default:
		return uint32(r), ErrInternal
	}
}

func (m *Tox) Conference_title(gid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK
	size, e := m.Conference_title_size(gid)
	if e != nil || size == 0 {
		return string(""), e
	}
	title := make([]byte, size)

	C.tox_conference_get_title(m.tox,
	C.uint32_t(gid),
	(*C.uint8_t)(&title[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		return string(title[:]), nil
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return string(title[:]), ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
		return string(title[:]), ErrConferenceTitleInvalidLength
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return string(title[:]), ErrConferenceTitleFailSend
	default:
		return string(title[:]), ErrInternal
	}
}

func (m *Tox) Conference_set_title(gid uint32, title string) error {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK
	var _title = []byte(title)

	C.tox_conference_set_title(m.tox,
	C.uint32_t(gid),
	(*C.uint8_t)(&_title[0]),
	C.size_t(len(title)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		return nil
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return ErrConferenceNotFound
	case C.TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
		return ErrConferenceTitleInvalidLength
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return ErrConferenceTitleFailSend
	default:
		return ErrInternal
	}
}

func (m *Tox) Conference_chatlist_size() uint32 {
	return uint32(C.tox_conference_get_chatlist_size(m.tox))
}

func (m *Tox) Conference_chatlist() []uint32 {
	size := m.Conference_chatlist_size()
	if size == 0 {
		return []uint32{}
	}
	vec := make([]uint32, size)
	C.tox_conference_get_chatlist(m.tox, (*C.uint32_t)(&vec[0]))
	return vec
}

func (m *Tox) Conference_type(gid uint32) (Conference_type, error) {
	var err C.TOX_ERR_CONFERENCE_GET_TYPE = C.TOX_ERR_CONFERENCE_GET_TYPE_OK

	r := C.tox_conference_get_type(m.tox, C.uint32_t(gid), &err)

	switch err {
	case C.TOX_ERR_CONFERENCE_GET_TYPE_OK:
		return Conference_type(r), nil
	case C.TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND:
		return Conference_type(r), ErrConferenceNotFound
	default:
		return Conference_type(r), ErrInternal
	}
}

// low-level custom packet sending and receiving
func (m *Tox) Friend_send_lossy_packet(fid uint32, data []byte) error {
	var err C.TOX_ERR_FRIEND_CUSTOM_PACKET = C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK

	C.tox_friend_send_lossy_packet(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&data[0]),
	C.size_t(len(data)),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK:
		return nil
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_NULL:
		return ErrNull
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID:
		return ErrFriendCustomPacketInvalid
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY:
		return ErrFriendCustomPacketEmpty
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG:
		return ErrFriendCustomPacketTooLong
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ:
		return ErrPacketQueueFull
	default:
		return ErrInternal
	}
}

func (m *Tox) Friend_send_lossless_packet(fid uint32, data []byte) error {
	var err C.TOX_ERR_FRIEND_CUSTOM_PACKET = C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK

	C.tox_friend_send_lossless_packet(m.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&data[0]),
	C.size_t(len(data)),
	&err)

	switch err {
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK:
		return nil
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_NULL:
		return ErrNull
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND:
		return ErrFriendNotFound
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED:
		return ErrFriendNotConnected
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID:
		return ErrFriendCustomPacketInvalid
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY:
		return ErrFriendCustomPacketEmpty
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG:
		return ErrFriendCustomPacketTooLong
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ:
		return ErrPacketQueueFull
	default:
		return ErrInternal
	}
}

// low-level network information
func (m *Tox) Self_dht_id() string {
	dht := make([]byte, PUBLIC_KEY_SIZE)
	C.tox_self_get_dht_id(m.tox,
	(*C.uint8_t)(&dht[0]))

	return hex.EncodeToString(dht)
}

func (m *Tox) Self_udp_port() (uint16, error) {
	var err C.TOX_ERR_GET_PORT = C.TOX_ERR_GET_PORT_OK

	r := C.tox_self_get_udp_port(m.tox,
	&err)

	switch err {
	case C.TOX_ERR_GET_PORT_OK:
		return uint16(r), nil
	case C.TOX_ERR_GET_PORT_NOT_BOUND:
		return uint16(r), ErrGetPortNotBound
	default:
		return uint16(r), ErrInternal
	}
}

func (m *Tox) Self_tcp_port() (uint16, error) {
	var err C.TOX_ERR_GET_PORT = C.TOX_ERR_GET_PORT_OK

	r := C.tox_self_get_tcp_port(m.tox,
	&err)

	switch err {
	case C.TOX_ERR_GET_PORT_OK:
		return uint16(r), nil
	case C.TOX_ERR_GET_PORT_NOT_BOUND:
		return uint16(r), ErrGetPortNotBound
	default:
		return uint16(r), ErrInternal
	}
}
// =================================
