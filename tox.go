package gtox

/*
#include <tox/tox.h>

typedef struct Tox_Options Tox_Options;

#define CB(x) \
static void set_##x(Tox* tox) { \
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

type User_status_t C.TOX_USER_STATUS
const (
	USER_STATUS_NONE = C.TOX_USER_STATUS_NONE
	USER_STATUS_AWAY = C.TOX_USER_STATUS_AWAY
	USER_STATUS_BUSY = C.TOX_USER_STATUS_BUSY
)
type Msg_t C.TOX_MESSAGE_TYPE
const (
	MSG_NORMAL = C.TOX_MESSAGE_TYPE_NORMAL
	MSG_ACTION = C.TOX_MESSAGE_TYPE_ACTION
)
type Proxy_t C.TOX_PROXY_TYPE
const (
	PROXY_TYPE_NONE = C.TOX_PROXY_TYPE_NONE
	PROXY_TYPE_HTTP = C.TOX_PROXY_TYPE_HTTP
	PROXY_TYPE_SOCKS5 = C.TOX_PROXY_TYPE_SOCKS5
)
type Savedata_t C.TOX_SAVEDATA_TYPE
const (
	SAVEDATA_TYPE_NONE = C.TOX_SAVEDATA_TYPE_NONE
	SAVEDATA_TYPE_TOX_SAVE = C.TOX_SAVEDATA_TYPE_TOX_SAVE
	SAVEDATA_TYPE_SECRET_KEY = C.TOX_SAVEDATA_TYPE_SECRET_KEY
)
type Connection_t C.TOX_CONNECTION
const (
	CONNECTION_NONE = C.TOX_CONNECTION_NONE
	CONNECTION_TCP = C.TOX_CONNECTION_TCP
	CONNECTION_UDP = C.TOX_CONNECTION_UDP
)
type File_control_t C.TOX_FILE_CONTROL
const (
	FILE_CONTROL_RESUME = C.TOX_FILE_CONTROL_RESUME
	FILE_CONTROL_PAUSE = C.TOX_FILE_CONTROL_PAUSE
	FILE_CONTROL_CANCEL = C.TOX_FILE_CONTROL_CANCEL
)
type Conference_type C.TOX_CONFERENCE_TYPE
const (
	CONFERENCE_TYPE_TEXT = C.TOX_CONFERENCE_TYPE_TEXT
	CONFERENCE_TYPE_AV = C.TOX_CONFERENCE_TYPE_AV
)
type Conference_state_change C.TOX_CONFERENCE_STATE_CHANGE
const (
	CONFERENCE_STATE_CHANGE_PEER_JOIN = C.TOX_CONFERENCE_STATE_CHANGE_PEER_JOIN
	CONFERENCE_STATE_CHANGE_PEER_EXIT = C.TOX_CONFERENCE_STATE_CHANGE_PEER_EXIT
	CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE = C.TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE
)

type Self_connection_status func(m *Tox, status Connection_t)
type Friend_name func(m *Tox, fid uint32, name []byte)
type Friend_status_message func(m *Tox, fid uint32, msg []byte)
type Friend_status func(m *Tox, fid uint32, status User_status_t)
type Friend_connection_status func(m *Tox, fid uint32, status Connection_t)
type Friend_typing func(m *Tox, fid uint32, is_typing bool)
type Friend_read_receipt func(m *Tox, fid uint32, mid uint32)
type Friend_request func(m *Tox, pubkey string, message string)
type Friend_message func(m *Tox, fid uint32, mtype Msg_t, message string)
type File_recv_control func(m *Tox, fid uint32, did uint32, control File_control_t)
type File_chunk_request func(m *Tox, fid uint32, did uint32, pos uint64, length uint32)
type File_recv func(m *Tox, fid uint32, did uint32, kind uint32, file_size uint64, filename string)
type File_recv_chunk func(m *Tox, fid uint32, did uint32, pos uint64, data []byte)
type Conference_invite func(m *Tox, fid uint32, t Conference_type, cookie []byte)
type Conference_message func(m *Tox, gid uint32, pid uint32, t Msg_t, message []byte)
type Conference_title func(m *Tox, gid uint32, pid uint32, title []byte)
type Conference_namelist_change func(m *Tox, gid uint32, pid uint32, change Conference_state_change)
type Friend_lossy_packet func(m *Tox, fid uint32, data []byte)
type Friend_lossless_packet func(m *Tox, fid uint32, data []byte)

type Tox_options struct {
	// private
	opt *C.Tox_Options
	// public
	Ipv6_enabled bool
	Udp_enabled bool
	Local_discovery_enabled bool
	Proxy_type Proxy_t
	Proxy_host string
	Proxy_port uint16
	Start_port uint16
	End_port uint16
	Tcp_port uint16
	Hole_punching_enabled bool
	Savedata_type Savedata_t
	Savedata_data []byte
	Savedata_length uint32
}

// main struct
type Tox struct {
	// private
	tox *C.Tox
	mtx sync.Mutex

	// private callback wrapper
	self_connection_status Self_connection_status
	friend_name Friend_name
	friend_status_message Friend_status_message
	friend_status Friend_status
	friend_connection_status Friend_connection_status
	friend_typing Friend_typing
	friend_read_receipt Friend_read_receipt
	friend_request Friend_request
	friend_message Friend_message
	file_recv_control File_recv_control
	file_chunk_request File_chunk_request
	file_recv File_recv
	file_recv_chunk File_recv_chunk
	conference_invite Conference_invite
	conference_message Conference_message
	conference_title Conference_title
	conference_namelist_change Conference_namelist_change
	friend_lossy_packet Friend_lossy_packet
	friend_lossless_packet Friend_lossless_packet
}
// =================================

// ========== callback wrapper =====
// connection lifecycle and event loop
//export cb_self_connection_status
func cb_self_connection_status(m *C.Tox, status C.TOX_CONNECTION, tox unsafe.Pointer) {
	(*Tox)(tox).self_connection_status((*Tox)(tox), Connection_t(status))
}

// friend list queries
//export cb_friend_name
func cb_friend_name(m *C.Tox, fid C.uint32_t, name *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_name((*Tox)(tox), uint32(fid), C.GoBytes(unsafe.Pointer(name), C.int(length)))
}
// friend-specific state queries
//export cb_friend_status_message
func cb_friend_status_message(m *C.Tox, fid C.uint32_t, msg *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_status_message((*Tox)(tox), uint32(fid), C.GoBytes(unsafe.Pointer(msg), C.int(length)))
}

//export cb_friend_status
func cb_friend_status(m *C.Tox, fid C.uint32_t, status C.TOX_USER_STATUS, tox unsafe.Pointer) {
	(*Tox)(tox).friend_status((*Tox)(tox), uint32(fid), User_status_t(status))
}

//export cb_friend_connection_status
func cb_friend_connection_status(m *C.Tox, fid C.uint32_t, status C.TOX_CONNECTION, tox unsafe.Pointer) {
	(*Tox)(tox).friend_connection_status((*Tox)(tox), uint32(fid), Connection_t(status))
}

//export cb_friend_typing
func cb_friend_typing(m *C.Tox, fid C.uint32_t, is_typing C.bool, tox unsafe.Pointer) {
	(*Tox)(tox).friend_typing((*Tox)(tox), uint32(fid), bool(is_typing))
}

// sending private messages
//export cb_friend_read_receipt
func cb_friend_read_receipt(m *C.Tox, fid C.uint32_t, mid C.uint32_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_read_receipt((*Tox)(tox), uint32(fid), uint32(mid))
}

// receiving private messages
//export cb_friend_request
func cb_friend_request(m *C.Tox, pubkey *C.uint8_t, msg *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	var pkey = C.GoBytes(unsafe.Pointer(pubkey), C.int(PUBLIC_KEY_SIZE))
	var pkey_hex = hex.EncodeToString(pkey)

	(*Tox)(tox).friend_request((*Tox)(tox),
		pkey_hex,
		C.GoStringN((*C.char)(unsafe.Pointer(msg)), C.int(length)))
}

//export cb_friend_message
func cb_friend_message(m *C.Tox, fid C.uint32_t, mtype C.TOX_MESSAGE_TYPE, msg *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_message((*Tox)(tox), uint32(fid), Msg_t(mtype), C.GoStringN((*C.char)(unsafe.Pointer(msg)), C.int(length)))
}

// file transmission: common
//export cb_file_recv_control
func cb_file_recv_control(m *C.Tox, fid C.uint32_t, did C.uint32_t, control C.TOX_FILE_CONTROL, tox unsafe.Pointer) {
	(*Tox)(tox).file_recv_control((*Tox)(tox), uint32(fid), uint32(did), File_control_t(control))
}

// file transmission: sending
//export cb_file_chunk_request
func cb_file_chunk_request(m *C.Tox, fid C.uint32_t, did C.uint32_t, pos C.uint64_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).file_chunk_request((*Tox)(tox), uint32(fid), uint32(did), uint64(pos), uint32(length))
}

// file transmission: receiving
//export cb_file_recv
func cb_file_recv(m *C.Tox, fid C.uint32_t, did C.uint32_t, kind C.uint32_t, file_size C.uint64_t, filename *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).file_recv((*Tox)(tox), uint32(fid), uint32(did), uint32(kind), uint64(file_size),
		C.GoStringN((*C.char)(unsafe.Pointer(filename)), C.int(length)))
}

//export cb_file_recv_chunk
func cb_file_recv_chunk(m *C.Tox, fid C.uint32_t, did C.uint32_t, pos C.uint64_t, data *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).file_recv_chunk((*Tox)(tox), uint32(fid), uint32(did), uint64(pos), C.GoBytes(unsafe.Pointer(data), C.int(length)))
}

// conference management
//export cb_conference_invite
func cb_conference_invite(m *C.Tox, fid C.uint32_t, t Conference_type, cookie *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).conference_invite((*Tox)(tox), uint32(fid), t, C.GoBytes(unsafe.Pointer(cookie), C.int(length)))
}

//export cb_conference_message
func cb_conference_message(m *C.Tox, gid C.uint32_t, pid C.uint32_t, t Msg_t, message *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).conference_message((*Tox)(tox), uint32(gid), uint32(pid), t, C.GoBytes(unsafe.Pointer(message), C.int(length)))
}

//export cb_conference_title
func cb_conference_title(m *C.Tox, gid C.uint32_t, pid C.uint32_t, title *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).conference_title((*Tox)(tox), uint32(gid), uint32(pid), C.GoBytes(unsafe.Pointer(title), C.int(length)))
}

//export cb_conference_namelist_change
func cb_conference_namelist_change(m *C.Tox, gid C.uint32_t, pid C.uint32_t, change Conference_state_change, tox unsafe.Pointer) {
	(*Tox)(tox).conference_namelist_change((*Tox)(tox), uint32(gid), uint32(pid), change)
}

// low-level custom packet sending and receiving
//export cb_friend_lossy_packet
func cb_friend_lossy_packet(m *C.Tox, fid C.uint32_t, data *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_lossy_packet((*Tox)(tox), uint32(fid), C.GoBytes(unsafe.Pointer(data), C.int(length)))
}

//export cb_friend_lossless_packet
func cb_friend_lossless_packet(m *C.Tox, fid C.uint32_t, data *C.uint8_t, length C.size_t, tox unsafe.Pointer) {
	(*Tox)(tox).friend_lossless_packet((*Tox)(tox), uint32(fid), C.GoBytes(unsafe.Pointer(data), C.int(length)))
}

// ================================

// =========== methods ============
// api version
func (this *Tox) Version_major() uint32 {
	return uint32(C.tox_version_major())
}

func (this *Tox) Version_minor() uint32 {
	return uint32(C.tox_version_minor())
}

func (this *Tox) Version_patch() uint32 {
	return uint32(C.tox_version_patch())
}

func (this *Tox) Version_is_compatible(m uint32, n uint32, p uint32) bool {
	return bool(C.tox_version_is_compatible(C.uint32_t(m),
		C.uint32_t(n),
		C.uint32_t(p)))
}

// startup options
func (this *Tox_options) New() (bool, error) {
	var err C.TOX_ERR_OPTIONS_NEW = C.TOX_ERR_OPTIONS_NEW_OK

	options := C.tox_options_new(&err)
	C.tox_options_default(options)

	switch err {
	case C.TOX_ERR_OPTIONS_NEW_OK:
		this.opt = options
		this.Ipv6_enabled = bool(C.tox_options_get_ipv6_enabled(options))
		this.Udp_enabled = bool(C.tox_options_get_udp_enabled(options))
		this.Local_discovery_enabled = bool(C.tox_options_get_local_discovery_enabled(options))
		this.Proxy_type = Proxy_t(C.tox_options_get_proxy_type(options))
		this.Proxy_host = C.GoString(C.tox_options_get_proxy_host(options))
		this.Proxy_port = uint16(C.tox_options_get_proxy_port(options))
		this.Start_port = uint16(C.tox_options_get_start_port(options))
		this.End_port = uint16(C.tox_options_get_end_port(options))
		this.Tcp_port = uint16(C.tox_options_get_tcp_port(options))
		this.Hole_punching_enabled = bool(C.tox_options_get_hole_punching_enabled(options))
		this.Savedata_type = Savedata_t(C.tox_options_get_savedata_type(options))
		this.Savedata_length = uint32(C.tox_options_get_savedata_length(options))
		this.Savedata_data =  C.GoBytes(unsafe.Pointer(C.tox_options_get_savedata_data(options)), C.int(this.Savedata_length))
		return true, nil
	case C.TOX_ERR_OPTIONS_NEW_MALLOC:
		C.tox_options_free(options)
		return false, errors.New("the function failed to allocate enough memory for the options struct.")
	default:
		C.tox_options_free(options)
		return false, errors.New("internal error.")
	}
}

func (this *Tox_options) Del() {
	C.tox_options_free(this.opt)
}

// creation and destruction
func (this *Tox) New(opt Tox_options) (bool, error) {
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
	C.tox_options_set_savedata_type(opt.opt, C.TOX_SAVEDATA_TYPE(opt.Savedata_type))
	if len(opt.Savedata_data) != 0 {
		C.tox_options_set_savedata_length(opt.opt, C.size_t(opt.Savedata_length))
		C.tox_options_set_savedata_data(opt.opt, (*C.uint8_t)(&opt.Savedata_data[0]), C.size_t(opt.Savedata_length))
	}

	r := C.tox_new(opt.opt,
		&err)

	switch err {
	case C.TOX_ERR_NEW_OK:
		this.tox = r
		return true, nil
	case C.TOX_ERR_NEW_NULL:
		C.tox_kill(r)
		return false, errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_NEW_MALLOC:
		C.tox_kill(r)
		return false, errors.New("the function was unable to allocate enough memory to store the internal structures for the Tox object.")
	case C.TOX_ERR_NEW_PORT_ALLOC:
		C.tox_kill(r)
		return false, errors.New("the function was unable to bind to a port.")
	case C.TOX_ERR_NEW_PROXY_BAD_TYPE:
		C.tox_kill(r)
		return false, errors.New("proxy_type was invalid.")
	case C.TOX_ERR_NEW_PROXY_BAD_HOST:
		C.tox_kill(r)
		return false, errors.New("proxy_type was valid but the proxy_host passed had an invalid format or was NULL.")
	case C.TOX_ERR_NEW_PROXY_BAD_PORT:
		C.tox_kill(r)
		return false, errors.New("proxy_type was valid, but the proxy_port was invalid.")
	case C.TOX_ERR_NEW_PROXY_NOT_FOUND:
		C.tox_kill(r)
		return false, errors.New("the proxy address passed could not be resolved.")
	case C.TOX_ERR_NEW_LOAD_ENCRYPTED:
		C.tox_kill(r)
		return false, errors.New("the byte array to be loaded contained an encrypted save.")
	case C.TOX_ERR_NEW_LOAD_BAD_FORMAT:
		C.tox_kill(r)
		return false, errors.New("the data format was invalid.")
	default:
		C.tox_kill(r)
		return false, errors.New("internal error.")
	}
}

func (this *Tox) Kill() {
	C.tox_kill(this.tox)
}

func (this *Tox) Savedata_size() uint32 {
	return uint32(C.tox_get_savedata_size(this.tox))
}

func (this *Tox) Savedata() []byte {
	var size = this.Savedata_size()
	var data = make([]byte, size)
	C.tox_get_savedata(this.tox, (*C.uint8_t)(&data[0]))
	return data
}

// connection lifecycle and event loop
func (this *Tox) Bootstrap(addr string, port uint16, pkey string) (bool, error) {
	var err C.TOX_ERR_BOOTSTRAP = C.TOX_ERR_BOOTSTRAP_OK
	var pubkey,_ = hex.DecodeString(pkey)

	r := C.tox_bootstrap(this.tox,
		C.CString(addr),
		C.uint16_t(port),
		(*C.uint8_t)(&pubkey[0]),
		&err)

	switch err {
	case C.TOX_ERR_BOOTSTRAP_OK:
		return bool(r), nil
	case C.TOX_ERR_BOOTSTRAP_NULL:
		return bool(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_BOOTSTRAP_BAD_HOST:
		return bool(r), errors.New("the address could not be resolved to an IP address, or the IP address passed was invalid.")
	case C.TOX_ERR_BOOTSTRAP_BAD_PORT:
		return bool(r), errors.New("the port passed was invalid. The valid port range is (1, 65535).")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Add_tcp_relay(addr string, port uint16, pkey string) (bool, error) {
	var err C.TOX_ERR_BOOTSTRAP = C.TOX_ERR_BOOTSTRAP_OK
	var pubkey,_ = hex.DecodeString(pkey)

	r := C.tox_add_tcp_relay(this.tox,
		C.CString(addr),
		C.uint16_t(port),
		(*C.uint8_t)(&pubkey[0]),
		&err)

	switch err {
	case C.TOX_ERR_BOOTSTRAP_OK:
		return bool(r), nil
	case C.TOX_ERR_BOOTSTRAP_NULL:
		return bool(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_BOOTSTRAP_BAD_HOST:
		return bool(r), errors.New("the address could not be resolved to an IP address, or the IP address passed was invalid.")
	case C.TOX_ERR_BOOTSTRAP_BAD_PORT:
		return bool(r), errors.New("the port passed was invalid. The valid port range is (1, 65535).")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Self_connection_status() Connection_t {
	return Connection_t(C.tox_self_get_connection_status(this.tox))
}

func (this *Tox) Callback_self_connection_status(cbfn Self_connection_status) {
	this.self_connection_status = cbfn
	C.set_self_connection_status(this.tox)
}

func (this *Tox) Iteration_interval() uint32 {
	return uint32(C.tox_iteration_interval(this.tox))
}

func (this *Tox) Iterate() {
	this.mtx.Lock()
	C.tox_iterate(this.tox, unsafe.Pointer(this))
	this.mtx.Unlock()
}

// internal client information
func (this *Tox) Self_address() string {
	var addr = make([]byte, ADDRESS_SIZE)
	C.tox_self_get_address(this.tox, (*C.uint8_t)(&addr[0]))
	return hex.EncodeToString(addr)
}

func (this *Tox) Self_set_nospam(nospam uint32) {
	C.tox_self_set_nospam(this.tox, C.uint32_t(nospam))
}

func (this *Tox) Self_nospam() uint32 {
	return uint32(C.tox_self_get_nospam(this.tox))
}

func (this *Tox) Self_public_key() string {
	var pubkey = make([]byte, PUBLIC_KEY_SIZE)

	C.tox_self_get_public_key(this.tox,
		(*C.uint8_t)(&pubkey[0]))

	return hex.EncodeToString(pubkey)
}

func (this *Tox) Self_secret_key() string {
	var seckey = make([]byte, SECRET_KEY_SIZE)

	C.tox_self_get_secret_key(this.tox,
		(*C.uint8_t)(&seckey[0]))

	return hex.EncodeToString(seckey)
}

// user-visible client info 
func (this *Tox) Self_set_name(name string) (bool, error) {
	var err C.TOX_ERR_SET_INFO = C.TOX_ERR_SET_INFO_OK
	var _name = []byte(name)

	r := C.tox_self_set_name(this.tox,
		(*C.uint8_t)(&_name[0]),
		C.size_t(len(_name)),
		&err)

	switch err {
	case C.TOX_ERR_SET_INFO_OK:
		return bool(r), nil
	case C.TOX_ERR_SET_INFO_NULL:
		return bool(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_SET_INFO_TOO_LONG:
		return bool(r), errors.New("information length exceeded maximum permissible size.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Self_name_size() uint32 {
	return uint32(C.tox_self_get_name_size(this.tox))
}

func (this *Tox) Self_name() string {
	var size = this.Self_name_size()
	var name = make([]byte, size)
	C.tox_self_get_name(this.tox, (*C.uint8_t)(&name[0]))
	return string(name)
}

func (this *Tox) Self_set_status_message(message string) (bool, error) {
	var err C.TOX_ERR_SET_INFO = C.TOX_ERR_SET_INFO_OK
	var msg =  []byte(message)

	r := C.tox_self_set_status_message(this.tox,
		(*C.uint8_t)(&msg[0]),
		C.size_t(len(msg)),
		&err)

	switch err {
	case C.TOX_ERR_SET_INFO_OK:
		return bool(r), nil
	case C.TOX_ERR_SET_INFO_NULL:
		return bool(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_SET_INFO_TOO_LONG:
		return bool(r), errors.New("information length exceeded maximum permissible size.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Self_status_message_size() uint32 {
	return uint32(C.tox_self_get_status_message_size(this.tox))
}

func (this *Tox) Self_status_message() string {
	var size = this.Self_status_message_size()
	var status_message = make([]byte, size)
	C.tox_self_get_status_message(this.tox, (*C.uint8_t)(&status_message[0]))
	return string(status_message)
}

func (this *Tox) Self_set_status(st User_status_t) {
	C.tox_self_set_status(this.tox,
		C.TOX_USER_STATUS(st))
}

func (this *Tox) Self_status() User_status_t {
	return User_status_t(C.tox_self_get_status(this.tox))
}

// friend list management
func (this *Tox) Friend_add(address string, message string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_ADD = C.TOX_ERR_FRIEND_ADD_OK
	var msg = []byte(message)
	var addr,_ = hex.DecodeString(address)

	r := C.tox_friend_add(this.tox,
		(*C.uint8_t)(&addr[0]),
		(*C.uint8_t)(&msg[0]),
		C.size_t(len(msg)),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_ADD_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_ADD_NULL:
		return uint32(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_ADD_TOO_LONG:
		return uint32(r), errors.New("the length of the friend request message exceeded TOX_MAX_FRIEND_REQUEST_LENGTH.")
	case C.TOX_ERR_FRIEND_ADD_NO_MESSAGE:
		return uint32(r), errors.New("the friend request message was empty.")
	case C.TOX_ERR_FRIEND_ADD_OWN_KEY:
		return uint32(r), errors.New("the friend address belongs to the sending client.")
	case C.TOX_ERR_FRIEND_ADD_ALREADY_SENT:
		return uint32(r), errors.New("a friend request has already been sent, or the address belongs to a friend that is already on the friend list.")
	case C.TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
		return uint32(r), errors.New("the friend address checksum failed.")
	case C.TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
		return uint32(r), errors.New("the friend was already there, but the nospam value was different.")
	case C.TOX_ERR_FRIEND_ADD_MALLOC:
		return uint32(r), errors.New("a memory allocation failed when trying to increase the friend list size.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_add_norequest(pkey string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_ADD = C.TOX_ERR_FRIEND_ADD_OK
	var pubkey,_ = hex.DecodeString(pkey)

	r := C.tox_friend_add_norequest(this.tox,
		(*C.uint8_t)(&pubkey[0]),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_ADD_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_ADD_NULL:
		return uint32(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_ADD_TOO_LONG:
		return uint32(r), errors.New("the length of the friend request message exceeded TOX_MAX_FRIEND_REQUEST_LENGTH.")
	case C.TOX_ERR_FRIEND_ADD_OWN_KEY:
		return uint32(r), errors.New("the friend address belongs to the sending client.")
	case C.TOX_ERR_FRIEND_ADD_ALREADY_SENT:
		return uint32(r), errors.New("a friend request has already been sent, or the address belongs to a friend that is already on the friend list.")
	case C.TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
		return uint32(r), errors.New("the friend address checksum failed.")
	case C.TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
		return uint32(r), errors.New("the friend was already there, but the nospam value was different.")
	case C.TOX_ERR_FRIEND_ADD_MALLOC:
		return uint32(r), errors.New("a memory allocation failed when trying to increase the friend list size.")
	case C.TOX_ERR_FRIEND_ADD_NO_MESSAGE:
		fallthrough
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_delete(fid uint32) (bool, error) {
	var err C.TOX_ERR_FRIEND_DELETE = C.TOX_ERR_FRIEND_DELETE_OK

	r := C.tox_friend_delete(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_DELETE_OK:
		return bool(r), nil
	case C.TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND:
		return bool(r), errors.New("there was no friend with the given friend number. No friends were deleted.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

// friend list queries
func (this *Tox) Friend_by_public_key(pkey string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_BY_PUBLIC_KEY = C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK
	var pubkey,_ = hex.DecodeString(pkey)

	r := C.tox_friend_by_public_key(this.tox,
		(*C.uint8_t)(&pubkey[0]),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL:
		return uint32(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND:
		return uint32(r), errors.New("no friend with the given Public Key exists on the friend list.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_exist(fid uint32) bool {
	return bool(C.tox_friend_exists(this.tox, C.uint32_t(fid)))
}

func (this *Tox) Friend_list_size() uint32 {
	return uint32(C.tox_self_get_friend_list_size(this.tox))
}

func (this *Tox) Friend_list() []uint32 {
	var size = this.Friend_list_size()
	var list = make([]uint32, size)
	C.tox_self_get_friend_list(this.tox, (*C.uint32_t)(&list[0]))
	return list
}

func (this *Tox) Friend_public_key(fid uint32) (string, error) {
	var err C.TOX_ERR_FRIEND_GET_PUBLIC_KEY = C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK
	var key = make([]byte, PUBLIC_KEY_SIZE)

	r := C.tox_friend_get_public_key(this.tox,
		C.uint32_t(fid),
		(*C.uint8_t)(&key[0]),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK:
		if !bool(r) {
			return hex.EncodeToString(key), errors.New("internal error.")
		}
		return hex.EncodeToString(key), nil
	case C.TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND:
		return hex.EncodeToString(key), errors.New("no friend with the given number exists on the friend list.")
	default:
		return hex.EncodeToString(key), errors.New("internal error.")
	}
}

func (this *Tox) Friend_last_online(fid uint32) (time.Time, error) {
	var err C.TOX_ERR_FRIEND_GET_LAST_ONLINE = C.TOX_ERR_FRIEND_GET_LAST_ONLINE_OK

	r := C.tox_friend_get_last_online(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_GET_LAST_ONLINE_OK:
		return time.Unix(int64(r), 0), nil
	case C.TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND:
		return time.Unix(int64(r), 0), errors.New("no friend with the given number exists on the friend list.")
	default:
		return time.Unix(int64(r), 0), errors.New("internal error.")
	}
}

// friend-specific state queries 
func (this *Tox) Friend_name_size(fid uint32) (uint32, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_name_size(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return uint32(r), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return uint32(r), errors.New("the friend_number did not designate a valid friend.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_name(fid uint32) (string ,error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK
	var size, invalid = this.Friend_name_size(fid)
	if invalid != nil {
		return string(""), invalid
	}
	var name = make([]byte, size)

	r := C.tox_friend_get_name(this.tox,
		C.uint32_t(fid),
		(*C.uint8_t)(&name[0]),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		if !bool(r) {
			return string(name), errors.New("internal error.")
		}
		return string(name), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return string(name), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return string(name), errors.New("the friend_number did not designate a valid friend.")
	default:
		return string(name), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_name(cbfn Friend_name) {
	this.friend_name = cbfn
	C.set_friend_name(this.tox)
}

func (this *Tox) Friend_status_message_size(fid uint32) (uint32, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_status_message_size(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return uint32(r), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return uint32(r), errors.New("the friend_number did not designate a valid friend.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_status_message(fid uint32) (string, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK
	var size, invalid = this.Friend_status_message_size(fid)
	if invalid != nil {
		return string(""), invalid
	}
	var msg = make([]byte, size)

	r := C.tox_friend_get_status_message(this.tox,
		C.uint32_t(fid),
		(*C.uint8_t)(&msg[0]),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		if !bool(r) {
			return string(msg), errors.New("internal error.")
		}
		return string(msg), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return string(msg), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return string(msg), errors.New("the friend_number did not designate a valid friend.")
	default:
		return string(msg), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_status_message(cbfn Friend_status_message) {
	this.friend_status_message = cbfn
	C.set_friend_status_message(this.tox)
}

func (this *Tox) Friend_status(fid uint32) (User_status_t, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_status_message_size(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return User_status_t(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return User_status_t(r), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return User_status_t(r), errors.New("the friend_number did not designate a valid friend.")
	default:
		return User_status_t(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_status(cbfn Friend_status) {
	this.friend_status = cbfn
	C.set_friend_status(this.tox)
}

func (this *Tox) Friend_connection_status(fid uint32) (Connection_t, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_connection_status(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return Connection_t(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return Connection_t(r), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return Connection_t(r), errors.New("the friend_number did not designate a valid friend.")
	default:
		return Connection_t(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_connection_status(cbfn Friend_connection_status) {
	this.friend_connection_status = cbfn
	C.set_friend_connection_status(this.tox)
}

func (this *Tox) Friend_get_typing(fid uint32) (bool, error) {
	var err C.TOX_ERR_FRIEND_QUERY = C.TOX_ERR_FRIEND_QUERY_OK

	r := C.tox_friend_get_typing(this.tox,
		C.uint32_t(fid),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_QUERY_OK:
		return bool(r), nil
	case C.TOX_ERR_FRIEND_QUERY_NULL:
		return bool(r), errors.New("the pointer parameter for storing the query result was nil.")
	case C.TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number did not designate a valid friend.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_typing(cbfn Friend_typing) {
	this.friend_typing = cbfn
	C.set_friend_typing(this.tox)
}

// send private messages
func (this *Tox) Self_set_typing(fid uint32, typing bool) (bool, error) {
	var err C.TOX_ERR_SET_TYPING = C.TOX_ERR_SET_TYPING_OK

	r := C.tox_self_set_typing(this.tox,
		C.uint32_t(fid),
		C.bool(typing),
		&err)

	switch err {
	case C.TOX_ERR_SET_TYPING_OK:
		return bool(r), nil
	case C.TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_send_message(fid uint32, mtype Msg_t, message string) (uint32, error) {
	var err C.TOX_ERR_FRIEND_SEND_MESSAGE = C.TOX_ERR_FRIEND_SEND_MESSAGE_OK
	var msg = []byte(message)

	r := C.tox_friend_send_message(this.tox,
		C.uint32_t(fid),
		C.TOX_MESSAGE_TYPE(mtype),
		(*C.uint8_t)(&msg[0]),
		C.size_t(len(msg)),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_OK:
		return uint32(r), nil
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_NULL:
		return uint32(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND:
		return uint32(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED:
		return uint32(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ:
		return uint32(r), errors.New("an allocation error occurred while increasing the send queue size.")
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG:
		return uint32(r), errors.New("message length exceeded MAX_MESSAGE_LENGTH.")
	case C.TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY:
		return uint32(r), errors.New("attempted to send a zero-length message.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_read_receipt(cbfn Friend_read_receipt) {
	this.friend_read_receipt = cbfn
	C.set_friend_read_receipt(this.tox)
}

// receiving private messages
func (this *Tox) Callback_friend_request(cbfn Friend_request) {
	this.friend_request = cbfn
	C.set_friend_request(this.tox)
}

func (this *Tox) Callback_friend_message(cbfn Friend_message) {
	this.friend_message = cbfn
	C.set_friend_message(this.tox)
}

// file transmission: common
func (this *Tox) Hash(data []byte) (bool, [HASH_LENGTH]byte) {
	var hash [HASH_LENGTH]byte

	r := C.tox_hash((*C.uint8_t)(&hash[0]), (*C.uint8_t)(&data[0]), C.size_t(len(data)))

	return bool(r), hash
}

func (this *Tox) File_control(fid uint32, did uint32, control File_control_t) (bool, error) {
	var err C.TOX_ERR_FILE_CONTROL = C.TOX_ERR_FILE_CONTROL_OK

	r := C.tox_file_control(this.tox,
		C.uint32_t(fid),
		C.uint32_t(fid),
		C.TOX_FILE_CONTROL(control),
		&err)

	switch err {
	case C.TOX_ERR_FILE_CONTROL_OK:
		return bool(r), nil
	case C.TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FILE_CONTROL_NOT_FOUND:
		return bool(r), errors.New("no file transfer with the given file number was found for the given friend.")
	case C.TOX_ERR_FILE_CONTROL_NOT_PAUSED:
		return bool(r), errors.New("a RESUME control was sent, but the file transfer is running normally.")
	case C.TOX_ERR_FILE_CONTROL_DENIED:
		return bool(r), errors.New("a RESUME control was sent, but the file transfer was paused by the other party.")
	case C.TOX_ERR_FILE_CONTROL_ALREADY_PAUSED:
		return bool(r), errors.New("a PAUSE control was sent, but the file transfer was already paused.")
	case C.TOX_ERR_FILE_CONTROL_SENDQ:
		return bool(r), errors.New("packet queue is full.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_file_recv_control(cbfn File_recv_control) {
	this.file_recv_control = cbfn
	C.set_file_recv_control(this.tox)
}

func (this *Tox) File_seek(fid uint32, did uint32, pos uint64) (bool, error) {
	var err C.TOX_ERR_FILE_SEEK = C.TOX_ERR_FILE_SEEK_OK

	r := C.tox_file_seek(this.tox,
		C.uint32_t(fid),
		C.uint32_t(did),
		C.uint64_t(pos),
		&err)

	switch err {
	case C.TOX_ERR_FILE_SEEK_OK:
		return bool(r), nil
	case C.TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FILE_SEEK_NOT_FOUND:
		return bool(r), errors.New("no file transfer with the given file number was found for the given friend.")
	case C.TOX_ERR_FILE_SEEK_DENIED:
		return bool(r), errors.New("file was not in a state where it could be seeked.")
	case C.TOX_ERR_FILE_SEEK_INVALID_POSITION:
		return bool(r), errors.New("seek position was invalid.")
	case C.TOX_ERR_FILE_SEEK_SENDQ:
		return bool(r), errors.New("packet queue is full.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) File_file_id(fid uint32, did uint32) ([FILE_ID_LENGTH]byte, error) {
	var err C.TOX_ERR_FILE_GET = C.TOX_ERR_FILE_GET_OK
	var file_id [FILE_ID_LENGTH]byte

	r := C.tox_file_get_file_id(this.tox,
		C.uint32_t(fid),
		C.uint32_t(did),
		(*C.uint8_t)(&file_id[0]),
		&err)

	switch err {
	case C.TOX_ERR_FILE_GET_OK:
		if !bool(r) {
			return file_id, errors.New("internal error.")
		}
		return file_id, nil
	case C.TOX_ERR_FILE_GET_NULL:
		return file_id, errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FILE_GET_FRIEND_NOT_FOUND:
		return file_id, errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOX_ERR_FILE_GET_NOT_FOUND:
		return file_id, errors.New("no file transfer with the given file number was found for the given friend.")
	default:
		return file_id, errors.New("internal error.")
	}
}

// file transmission: sending
func (this *Tox) File_send(fid uint32, kind uint32, size uint64, file_id [FILE_ID_LENGTH]byte, filename string) (uint32, error) {
	var err C.TOX_ERR_FILE_SEND = C.TOX_ERR_FILE_SEND_OK
	var fname = []byte(filename)

	r := C.tox_file_send(this.tox,
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
		return uint32(r), errors.New("one of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND:
		return uint32(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED:
		return uint32(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FILE_SEND_NAME_TOO_LONG:
		return uint32(r), errors.New("filename length exceeded TOX_MAX_FILENAME_LENGTH bytes.")
	case C.TOX_ERR_FILE_SEND_TOO_MANY:
		return uint32(r), errors.New("too many ongoing transfers.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) File_send_chunk(fid uint32, did uint32, pos uint64, data []byte) (bool, error) {
	var err C.TOX_ERR_FILE_SEND_CHUNK = C.TOX_ERR_FILE_SEND_CHUNK_OK

	r := C.tox_file_send_chunk(this.tox,
		C.uint32_t(fid),
		C.uint32_t(did),
		C.uint64_t(pos),
		(*C.uint8_t)(&data[0]),
		C.size_t(len(data)),
		&err)

	switch err {
	case C.TOX_ERR_FILE_SEND_CHUNK_OK:
		return bool(r), nil
	case C.TOX_ERR_FILE_SEND_CHUNK_NULL:
		return bool(r), errors.New("the length parameter was non-zero, but data was NULL.")
	case C.TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend_number passed did not designate a valid friend.")
	case C.TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND:
		return bool(r), errors.New("no file transfer with the given file number was found for the given friend.")
	case C.TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING:
		return bool(r), errors.New("file transfer was found but isn't in a transferring state.")
	case C.TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH:
		return bool(r), errors.New("attempted to send more or less data than requested.")
	case C.TOX_ERR_FILE_SEND_CHUNK_SENDQ:
		return bool(r), errors.New("packet queue is full.")
	case C.TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION:
		return bool(r), errors.New("position parameter was wrong.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_file_chunk_request(cbfn File_chunk_request) {
	this.file_chunk_request = cbfn
	C.set_file_chunk_request(this.tox)
}

// file transmission: receiving
func (this *Tox) Callback_file_recv(cbfn File_recv) {
	this.file_recv = cbfn
	C.set_file_recv(this.tox)
}

func (this *Tox) Callback_file_recv_chunk(cbfn File_recv_chunk) {
	this.file_recv_chunk = cbfn
	C.set_file_recv_chunk(this.tox)
}

// conference management
func (this *Tox) Callback_conference_invite(cbfn Conference_invite) {
	this.conference_invite = cbfn
	C.set_conference_invite(this.tox)
}

func (this *Tox) Callback_conference_message(cbfn Conference_message) {
	this.conference_message = cbfn
	C.set_conference_message(this.tox)
}

func (this *Tox) Callback_conference_title(cbfn Conference_title) {
	this.conference_title = cbfn
	C.set_conference_title(this.tox)
}

func (this *Tox) Callback_conference_namelist_change(cbfn Conference_namelist_change) {
	this.conference_namelist_change = cbfn
	C.set_conference_namelist_change(this.tox)
}

func (this *Tox) Conference_new() (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_NEW = C.TOX_ERR_CONFERENCE_NEW_OK

	r := C.tox_conference_new(this.tox,
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_NEW_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_NEW_INIT:
		return uint32(r), errors.New("instance failed to initialize.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_del(gid uint32) (bool, error) {
	var err C.TOX_ERR_CONFERENCE_DELETE = C.TOX_ERR_CONFERENCE_DELETE_OK

	r := C.tox_conference_delete(this.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_DELETE_OK:
		return bool(r), nil
	case C.TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND:
		return bool(r), errors.New("group not found, invalid group number.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_peer_count(gid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	r := C.tox_conference_peer_count(this.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return uint32(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return uint32(r), errors.New("invite packet failed to send.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_peer_name_size(gid uint32, pid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	r := C.tox_conference_peer_get_name_size(this.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return uint32(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return uint32(r), errors.New("invite packet failed to send.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_peer_name(gid uint32, pid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK
	var name[MAX_NAME_LENGTH] byte

	C.tox_conference_peer_get_name(this.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	(*C.uint8_t)(&name[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return string(name[:]), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return string(name[:]), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return string(name[:]), errors.New("invite packet failed to send.")
	default:
		return string(name[:]), errors.New("internal error.")
	}
}

func (this *Tox) Conference_peer_public_key(gid uint32, pid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK
	var key = make([]byte, PUBLIC_KEY_SIZE)

	C.tox_conference_peer_get_public_key(this.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	(*C.uint8_t)(&key[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return hex.EncodeToString(key), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return hex.EncodeToString(key), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return hex.EncodeToString(key), errors.New("invite packet failed to send.")
	default:
		return hex.EncodeToString(key), errors.New("internal error.")
	}
}

func (this *Tox) Conference_peer_number_is_ours(gid uint32, pid uint32) (bool, error) {
	var err C.TOX_ERR_CONFERENCE_PEER_QUERY = C.TOX_ERR_CONFERENCE_PEER_QUERY_OK

	r := C.tox_conference_peer_number_is_ours(this.tox,
	C.uint32_t(gid),
	C.uint32_t(pid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_OK:
		return bool(r), nil
	case C.TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
		return bool(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return bool(r), errors.New("invite packet failed to send.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_invite(fid uint32, gid uint32) (bool, error) {
	var err C.TOX_ERR_CONFERENCE_INVITE = C.TOX_ERR_CONFERENCE_INVITE_OK

	r := C.tox_conference_invite(this.tox,
	C.uint32_t(fid),
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_INVITE_OK:
		return bool(r), nil
	case C.TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND:
		return bool(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
		return bool(r), errors.New("invite packet failed to send.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_join(fid uint32, cookie []byte) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_JOIN = C.TOX_ERR_CONFERENCE_JOIN_OK

	r := C.tox_conference_join(this.tox,
	C.uint32_t(fid),
	(*C.uint8_t)(&cookie[0]),
	C.size_t(len(cookie)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_JOIN_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH:
		return uint32(r), errors.New("cookie passed has an invalid length.")
	case C.TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE:
		return uint32(r), errors.New("wrong group type or invalid cookie.")
	case C.TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND:
		return uint32(r), errors.New("friend not found, invalid friend number.")
	case C.TOX_ERR_CONFERENCE_JOIN_DUPLICATE:
		return uint32(r), errors.New("joined already.")
	case C.TOX_ERR_CONFERENCE_JOIN_INIT_FAIL:
		return uint32(r), errors.New("group instance failed to initialize.")
	case C.TOX_ERR_CONFERENCE_JOIN_FAIL_SEND:
		return uint32(r), errors.New("join packet failed to send.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_send_message(gid uint32, t Msg_t, message string) (bool, error) {
	var err C.TOX_ERR_CONFERENCE_SEND_MESSAGE = C.TOX_ERR_CONFERENCE_SEND_MESSAGE_OK
	var msg = []byte(message)

	r := C.tox_conference_send_message(this.tox,
	C.uint32_t(gid),
	C.TOX_MESSAGE_TYPE(t),
	(*C.uint8_t)(&msg[0]),
	C.size_t(len(msg)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_OK:
		return bool(r), nil
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND:
		return bool(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG:
		return bool(r), errors.New("msg is too long, len.")
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION:
		return bool(r), errors.New("lost connection.")
	case C.TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND:
		return bool(r), errors.New("message packet failed to send.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_title_size(gid uint32) (uint32, error) {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK

	r := C.tox_conference_get_title_size(this.tox,
	C.uint32_t(gid),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		return uint32(r), nil
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return uint32(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return uint32(r), errors.New("title packet failed to send.")
	default:
		return uint32(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_title(gid uint32) (string, error) {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK
	var str[MAX_NAME_LENGTH] byte

	r := C.tox_conference_get_title(this.tox,
	C.uint32_t(gid),
	(*C.uint8_t)(&str[0]),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		if !bool(r) {
			return string(str[:]), errors.New("internal error.")
		}
		return string(str[:]), nil
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return string(str[:]), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
		return string(str[:]), errors.New("title is too long or empty, len.")
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return string(str[:]), errors.New("title packet failed to send.")
	default:
		return string(str[:]), errors.New("internal error.")
	}
}

func (this *Tox) Conference_set_title(gid uint32, title string) (bool, error) {
	var err C.TOX_ERR_CONFERENCE_TITLE = C.TOX_ERR_CONFERENCE_TITLE_OK
	var _title = []byte(title)

	r := C.tox_conference_set_title(this.tox,
	C.uint32_t(gid),
	(*C.uint8_t)(&_title[0]),
	C.size_t(len(title)),
	&err)

	switch err {
	case C.TOX_ERR_CONFERENCE_TITLE_OK:
		return bool(r), nil
	case C.TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
		return bool(r), errors.New("group not found, invalid group number.")
	case C.TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
		return bool(r), errors.New("title is too long or empty, len.")
	case C.TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
		return bool(r), errors.New("title packet failed to send.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Conference_chatlist_size() uint32 {
	return uint32(C.tox_conference_get_chatlist_size(this.tox))
}

func (this *Tox) Conference_chatlist() []uint32 {
	var size = this.Conference_chatlist_size()
	var vec = make([]uint32, size)
	C.tox_conference_get_chatlist(this.tox, (*C.uint32_t)(&vec[0]))
	return vec
}

func (this *Tox) Conference_type(gid uint32) (Conference_type, error) {
	var err C.TOX_ERR_CONFERENCE_GET_TYPE = C.TOX_ERR_CONFERENCE_GET_TYPE_OK

	r := C.tox_conference_get_type(this.tox, C.uint32_t(gid), &err)

	switch err {
	case C.TOX_ERR_CONFERENCE_GET_TYPE_OK:
		return Conference_type(r), nil
	case C.TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND:
		return Conference_type(r), errors.New("group not found, invalid group number.")
	default:
		return Conference_type(r), errors.New("internal error.")
	}
}

// low-level custom packet sending and receiving
func (this *Tox) Friend_send_lossy_packet(fid uint32, data []byte) (bool, error) {
	var err C.TOX_ERR_FRIEND_CUSTOM_PACKET = C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK

	r := C.tox_friend_send_lossy_packet(this.tox,
		C.uint32_t(fid),
		(*C.uint8_t)(&data[0]),
		C.size_t(len(data)),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK:
		return bool(r), nil
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_NULL:
		return bool(r), errors.New("oe of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID:
		return bool(r), errors.New("the first byte of data was not in the specified range for the packet type.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY:
		return bool(r), errors.New("attempted to send an empty packet.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG:
		return bool(r), errors.New("packet data length exceeded TOX_MAX_CUSTOM_PACKET_SIZE.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ:
		return bool(r), errors.New("packet queue is full.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Friend_send_lossless_packet(fid uint32, data []byte) (bool, error) {
	var err C.TOX_ERR_FRIEND_CUSTOM_PACKET = C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK

	r := C.tox_friend_send_lossless_packet(this.tox,
		C.uint32_t(fid),
		(*C.uint8_t)(&data[0]),
		C.size_t(len(data)),
		&err)

	switch err {
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_OK:
		return bool(r), nil
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_NULL:
		return bool(r), errors.New("oe of the arguments to the function was NULL when it was not expected.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND:
		return bool(r), errors.New("the friend number did not designate a valid friend.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED:
		return bool(r), errors.New("this client is currently not connected to the friend.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID:
		return bool(r), errors.New("the first byte of data was not in the specified range for the packet type.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY:
		return bool(r), errors.New("attempted to send an empty packet.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG:
		return bool(r), errors.New("packet data length exceeded TOX_MAX_CUSTOM_PACKET_SIZE.")
	case C.TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ:
		return bool(r), errors.New("packet queue is full.")
	default:
		return bool(r), errors.New("internal error.")
	}
}

func (this *Tox) Callback_friend_lossy_packet(cbfn Friend_lossy_packet) {
	this.friend_lossy_packet = cbfn
	C.set_friend_lossy_packet(this.tox)
}

func (this *Tox) Callback_friend_lossless_packet(cbfn Friend_lossless_packet) {
	this.friend_lossless_packet = cbfn
	C.set_friend_lossless_packet(this.tox)
}

// low-level network information
func (this *Tox) Self_dht_id() string {
	var dht = make([]byte, PUBLIC_KEY_SIZE)
	C.tox_self_get_dht_id(this.tox,
		(*C.uint8_t)(&dht[0]))

	return hex.EncodeToString(dht)
}

func (this *Tox) Self_udp_port() (uint16, error) {
	var err C.TOX_ERR_GET_PORT = C.TOX_ERR_GET_PORT_OK

	r := C.tox_self_get_udp_port(this.tox,
		&err)

	switch err {
	case C.TOX_ERR_GET_PORT_OK:
		return uint16(r), nil
	case C.TOX_ERR_GET_PORT_NOT_BOUND:
		return uint16(r), errors.New("the instance was not bound to any port.")
	default:
		return uint16(r), errors.New("internal error.")
	}
}

func (this *Tox) Self_tcp_port() (uint16, error) {
	var err C.TOX_ERR_GET_PORT = C.TOX_ERR_GET_PORT_OK

	r := C.tox_self_get_tcp_port(this.tox,
		&err)

	switch err {
	case C.TOX_ERR_GET_PORT_OK:
		return uint16(r), nil
	case C.TOX_ERR_GET_PORT_NOT_BOUND:
		return uint16(r), errors.New("the instance was not bound to any port.")
	default:
		return uint16(r), errors.New("internal error.")
	}
}
// =================================
