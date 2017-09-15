package main

import (
	"os"
	"os/signal"
	"syscall"
	"encoding/json"
	"log"
	"bytes"
	"fmt"
	"time"
	"flag"
	"io"
	"io/ioutil"
	"sync"
	"context"
	"net"
	"net/http"
	"crypto/tls"
	"strings"
	"github.com/qiniu/api.v7/auth/qbox"
	"github.com/qiniu/api.v7/storage"
	"github.com/hashicorp/yamux"
	. "github.com/xhebox/gtox/tox"
)

const (
	DUMPBYTE_PACKET = 0xa0
	CLIENT_HANDSHAKE_PACKET = 0xa1
	SERVER_HANDSHAKE_PACKET = 0xa2
)

type node struct {
	Ipv4 string
	Ipv6 string
	Port uint16
	Tcp_ports []uint16
	Public_key string
	Status_udp bool
	Status_tcp bool
}

type Qiniu struct {
	Key string
	Sec string
	Url string
	Bucket string
}

type Tunnel struct {
	Server string
	Mtu int64
	AliveInterval string
	ConnTimeout string
	MaxStreamWindowSize int
}

type Config struct {
	Name string
	StMsg string
	Save string
	SaveMode int
	WikiFetch bool
	Log string

	Tun Tunnel
	Qiniu Qiniu

	Nodes []node
}

type tunnel struct {
	fid uint32
	sess *yamux.Session

	// write
	// buf: [0] = DUMPBYTE
	buf []byte

	// read
	// read used by muxlib
	// pipe_read used by tox callback
	read *io.PipeReader
	pipe_read *io.PipeWriter
}

type Bot struct {
	id string
	config string
	configMode int
	opt Config
	stime time.Time
	buf bytes.Buffer

	tunconfig *yamux.Config
	tun *tunnel

	tox_opt *Tox_options
	tox *Tox
	mtx sync.Mutex
}

var bot Bot

func min(a int, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func fetch_file(url string) (buf []byte, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res,e := client.Get(url)
	if e != nil {
		return nil, fmt.Errorf("failed to fetch url:", url, e)
	}
	defer res.Body.Close()


	body,e := ioutil.ReadAll(res.Body)
	if e != nil {
		return nil, fmt.Errorf("failed to read body:", url,  e)
	}

	return body, nil
}

func fetch_wiki_nodes() ([]node, error) {
	buf,e := fetch_file("https://nodes.tox.chat/json")
	if e != nil {
		return nil, e
	}

	var f []node

	dec := json.NewDecoder(bytes.NewReader(buf))
	var t json.Token
	for {
		t,e = dec.Token()
		if e != nil {
			break
		}

		if v,ok := t.(string); ok && v == "nodes" {
			break
		}
	}

	e = dec.Decode(&f)
	if e != nil {
		log.Println(e)
	}

	if e != nil {
		return nil, fmt.Errorf("failed to parsed json from wiki to get nodes:", e)
	}

	return f, nil
}

func fetch_qiniu_file(file string) (buf []byte, err error) {
	if bot.opt.Qiniu.Url == "none" {
		return nil, fmt.Errorf("please specific qiniu repo url")
	}

	return fetch_file("https://" + storage.MakePublicURL(bot.opt.Qiniu.Url, file))
}

func read_file(file string) (buf []byte, err error) {
	return ioutil.ReadFile(file)
}

func grab_file(mode int, file string, cb func(src []byte) error) error {
	if mode & 4 == 4 {
		buf,e := fetch_qiniu_file(file)
		if e != nil {
			return fmt.Errorf("failed to fetch remote file from qiniu:", file, e)
		} else {
			return cb(buf)
		}
	}

	if mode & 2 == 2 {
		buf,e := fetch_file(file)
		if e != nil {
			return fmt.Errorf("failed to fetch remote file from url:", file, e)
		} else {
			return cb(buf)
		}
	}

	if mode & 1 == 1 {
		buf,e := read_file(file)
		if e != nil {
			return fmt.Errorf("failed to open local file:", file, e)
		} else {
			return cb(buf)
		}
	}

	return nil
}

func config_parse(buf []byte) error {
	e := json.Unmarshal(buf, &bot.opt)
	if e != nil {
		return fmt.Errorf("failed to parse config file:", e)
	}
	return nil
}

func config_save(buf []byte) error {
	if len(buf) != 0 {
		bot.tox_opt.Savedata_length = uint32(len(buf))
		bot.tox_opt.Savedata_type = SAVEDATA_TYPE_TOX_SAVE
		bot.tox_opt.Savedata_data = buf
	}
	return nil
}

func update_qiniu_file(file string, src []byte) error {
	if bot.opt.Qiniu.Bucket == "none" || bot.opt.Qiniu.Key == "none" || bot.opt.Qiniu.Sec == "none" {
		return fmt.Errorf("please specific -qsec,-qkey,-qbucket to upload file")
	}

	cfg := &storage.Config{
		Zone: &storage.ZoneHuadong,
		UseHTTPS: false,
		UseCdnDomains: false,
	}
	putPolicy := &storage.PutPolicy{
		Scope: fmt.Sprintf("%s:%s", bot.opt.Qiniu.Bucket, file),
	}
	return storage.NewFormUploader(cfg).Put(context.Background(),
		&storage.PutRet{},
		putPolicy.UploadToken(qbox.NewMac(bot.opt.Qiniu.Key, bot.opt.Qiniu.Sec)),
		file,
		bytes.NewReader(src),
		int64(len(src)), nil)
}

func write_file(file string, src []byte) error {
	return ioutil.WriteFile(file, src, 0644)
}

func abort(para...interface{}) {
	bot.tox.StopIterateLoop()
	log.Fatalln(para...)
}

func save() error {
	bot.mtx.Lock()
	defer bot.mtx.Unlock()
	mode := bot.opt.SaveMode
	if mode & 5 != 0 {
		file := bot.opt.Save
		data := bot.tox.Savedata()
		if mode & 4 == 4 {
			if e := update_qiniu_file(file, data); e != nil {
				return fmt.Errorf("failed to upload save to qiniu:", file, e)
			}
		}

		if mode & 1 == 1 {
			if e := write_file(file, data); e != nil {
				return fmt.Errorf("failed to sync save to disk:", file, e)
			}
		}
	}
	return nil
}

func clean() {
	bot.mtx.Lock()
	defer bot.mtx.Unlock()

	if bot.tun != nil {
		bot.tun.Close()
	}
	bot.tox.Kill()
	bot.tox_opt.Del()
}

func handle_conn(conn net.Conn) {
	s := bot.tun
	if s == nil  {
		log.Println("cant open a stream, server not online")
		return
	}

	stream,e := s.sess.OpenStream()
	if e != nil {
		log.Println("cant open a stream:", e)
		return
	}
	defer stream.Close()
	defer conn.Close()

	buf := make([]byte, 512)
	n,e := conn.Read(buf)
	if e != nil {
		log.Println("cant read from local port:", e)
		return
	} else if buf[0] != 5 {
		log.Println("unknown socks version:", buf[0])
		return
	}
	conn.Write([]byte{0x05, 0x00})

	n,e = conn.Read(buf)
	if e != nil {
		log.Println("cant read from local port", e)
		return
	} else if buf[1] != 1 {
		log.Println("only support connect command(1), not command:", buf[1])
		return
	}

	buf[0] = CLIENT_HANDSHAKE_PACKET
	copy(buf[1:], buf[3:n])
	_,e = stream.Write(buf[:n-2])
	if e != nil {
		log.Println("failed to send handshake:", e)
		return
	}

	n,e = stream.Read(buf)
	if e != nil {
		log.Println("connection may failed on server:", e)
		return
	}

	if buf[0] != SERVER_HANDSHAKE_PACKET {
		log.Println("handshake failed")
		return
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	log.Println("handshake succeeded")

	go io.Copy(stream, conn)
	io.Copy(conn, stream)
}

func newtun(fid uint32) (*tunnel, error) {
		s := &tunnel{}
		s.fid = fid
		s.buf = make([]byte, bot.opt.Tun.Mtu+1)
		s.buf[0] = DUMPBYTE_PACKET
		s.read,s.pipe_read = io.Pipe()

		sess,e := yamux.Client(s, bot.tunconfig)
		if e != nil {
			return nil, fmt.Errorf("failed to create a new tunnel:", e)
    }
		s.sess = sess
		return s, nil
}

func (this *tunnel) to_read(data []byte) (n int, err error) {
	return this.pipe_read.Write(data[1:])
}

func (this *tunnel) Read(data []byte) (n int, err error) {
	return this.read.Read(data)
}

func (this *tunnel) Write(data []byte) (n int, err error) {
	rd := bytes.NewReader(data)
	buf := this.buf[1:]
	fid := this.fid
	n = 0
	defer bot.tox.Iterate()
	for {
		l,e := rd.Read(buf)
		if e == io.EOF {
			return n, nil
		}	else if e != nil {
			return n, e
		}

		if e := bot.tox.Friend_send_lossless_packet(fid, this.buf[:l+1]); e != nil {
			return n, e
		}
		n += l
		bot.tox.Iterate()
	}
	return n, nil
}

func (this *tunnel) Close() (err error) {
	if this.read != nil {
		this.read.Close()
	}
	if this.pipe_read != nil {
		this.pipe_read.Close()
	}
	return nil
}

func self_connection_status(m *Tox, ct Connection) {
	switch ct {
	case CONNECTION_NONE:
		log.Println("offline")
	case CONNECTION_TCP:
		log.Println("online with TCP")
	case CONNECTION_UDP:
		log.Println("online with UDP")
	}
}

func friend_name(m *Tox, fid uint32, name string) {
	log.Printf("friend name updated { fid: %d, name: %s }\n", fid, name)
}

func friend_status_message(m *Tox, fid uint32, msg string) {
	log.Printf("friend status msg updated { fid: %d, msg: %s }\n", fid, msg)
}

func friend_status(m *Tox, fid uint32, st User_status) {
	name,_ := m.Friend_name(fid)
	switch st {
	case USER_STATUS_NONE:
		log.Printf("{ fid: %d, name: %s } online without status\n", fid, name)
	case USER_STATUS_AWAY:
		log.Printf("{ fid: %d, name: %s } online with AWAY status\n", fid, name)
	case USER_STATUS_BUSY:
		log.Printf("{ fid: %d, name: %s } online with BUSY status\n", fid, name)
	}
}

func friend_connection_status(m *Tox, fid uint32, ct Connection) {
	name,_ := m.Friend_name(fid)
	switch ct {
	case CONNECTION_NONE:
		log.Printf("{ fid: %d, name: %s } offline\n", fid, name)
	case CONNECTION_TCP:
		log.Printf("{ fid: %d, name: %s } online with TCP\n", fid, name)
		if p,e := m.Friend_public_key(fid); e == nil && strings.HasPrefix(bot.opt.Tun.Server, p) {
			f,e := newtun(fid)
			if e != nil {
				bot.tun = nil
				log.Println(e)
				return
			}
			bot.tun = f
			log.Println("new tun")
		}
	case CONNECTION_UDP:
		log.Printf("{ fid: %d, name: %s } online with UDP\n", fid, name)
		if p,e := m.Friend_public_key(fid); e == nil && strings.HasPrefix(bot.opt.Tun.Server, p) {
			f,e := newtun(fid)
			if e != nil {
				bot.tun = nil
				log.Println(e)
				return
			}
			bot.tun = f
			log.Println("new tun")
		}
	}
}

func friend_request(m *Tox, pubkey string, message string) {
	if _,e := m.Friend_add_norequest(pubkey); e != nil {
		log.Println(e)
		return
	}

	fid,e := m.Friend_by_public_key(pubkey)
	if e != nil {
		log.Println(e)
		return
	}

	log.Printf("received friend request { pubkey: %s, fid: %d, msg: %s }\n", pubkey, fid, message)
}

func friend_message(m *Tox, fid uint32, mt Msg_type, msg string) {
	log.Printf("received msg { fid: %d, msg: %s }\n", fid, msg)

	bot.buf.Reset()
	c := strings.Split(msg, " ")

	if mt == MSG_NORMAL {
		switch c[0] {
		case "status":
			var count uint32
			for _,v := range m.Friend_list() {
				status,e := m.Friend_connection_status(v)
				if e == nil && status != CONNECTION_NONE {
					count++
				}
			}
			bot.buf.WriteString(fmt.Sprintln("Id: ", bot.id))
			bot.buf.WriteString(fmt.Sprintln("Uptime:", time.Now().Sub(bot.stime).String()))
			bot.buf.WriteString(fmt.Sprintf("Online: [ %d / %d ]", count, m.Friend_list_size()))
		default:
			bot.buf.WriteString(fmt.Sprintln("Id: ", bot.id))
			bot.buf.WriteString("Commands:\n")
			bot.buf.WriteString("status -- print current status\n")
		}
	}

	if bot.buf.Len() > 0 {
		m.Friend_send_message(fid, MSG_NORMAL, bot.buf.String())
	}
}

func friend_lossless_packet(m *Tox, fid uint32, data []byte) {
	if s := bot.tun; s != nil {
		s.to_read(data[:])
	}
}

func main() {
	bot.tox_opt = &Tox_options{}
	bot.tox = &Tox{}

	flag.StringVar(&bot.opt.Name, "name", "xhe", "bot name")
	flag.StringVar(&bot.opt.StMsg, "stmsg", "xhebot", "bot status msg")

	flag.StringVar(&bot.config, "config", "config.json", "config file path")
	flag.IntVar(&bot.configMode, "cmode", 1, "bit flag like unix permission, for now, only two options, qiniu|file")
	flag.StringVar(&bot.opt.Save, "save", "save.bin", "save file path")
	flag.IntVar(&bot.opt.SaveMode, "smode", 1, "same to config mode")
	flag.BoolVar(&bot.opt.WikiFetch, "wikifetch", false, "if fetch nodes from wiki, fetch when did not specific nodes, enable this to fetch nodes even there're nodes in config file")
	flag.StringVar(&bot.opt.Log, "log", "stderr", "log file name, could be set to stderr, stdout")

	flag.StringVar(&bot.opt.Tun.Server, "server", "none", "server id")
	flag.Int64Var(&bot.opt.Tun.Mtu, "mtu", 1280, fmt.Sprintln("tunnel mtu size, max", MAX_CUSTOM_PACKET_SIZE-1))
	flag.StringVar(&bot.opt.Tun.AliveInterval, "alive_interval", "30s", "tunnel keep alive interval")
	flag.StringVar(&bot.opt.Tun.ConnTimeout, "conn_timeout", "10s", "tunnel conn write time out")
	flag.IntVar(&bot.opt.Tun.MaxStreamWindowSize, "max_wnd", 256*1024, "tunnel max window size per stream")

	flag.StringVar(&bot.opt.Qiniu.Key, "qkey", "none", "qiniu access key")
	flag.StringVar(&bot.opt.Qiniu.Sec, "qsec", "none", "qiniu secret key")
	flag.StringVar(&bot.opt.Qiniu.Bucket, "qbucket", "none", "qiniu bucket name")
	flag.StringVar(&bot.opt.Qiniu.Url, "qurl", "none", "qiniu url, qiniu://www.xxxx.com, when set, try to fetch&store files from/to remote server")
	flag.Parse()

	var (
		w *os.File
		e error
	)
	switch bot.opt.Log {
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		if w,e = os.OpenFile(bot.opt.Log, os.O_RDWR|os.O_CREATE, 0755); e != nil {
			log.Println("failed to open log file, fallback to stderr", e)
			w = os.Stderr
		}
	}
	log.SetFlags(log.Lshortfile)
	log.SetOutput(w)
	if bot.tox_opt,e = NewOpt(); e != nil {
		abort("failed to create a new tox_options instance", e)
	}

	if e := grab_file(bot.configMode, bot.config, config_parse); e != nil {
		abort(e)
	}

	if e := grab_file(bot.opt.SaveMode, bot.opt.Save, config_save); e != nil {
		abort(e)
	}

	if bot.opt.Nodes == nil || bot.opt.WikiFetch {
		nodes,e := fetch_wiki_nodes()
		if e != nil {
			log.Println(e)
		}

		bot.opt.Nodes = nodes
		bot.opt.WikiFetch = true
	}

	if bot.opt.Tun.Server == "none" {
		abort("no server specified, exit")
	}

	if bot.opt.Tun.Mtu > MAX_CUSTOM_PACKET_SIZE-1 || bot.opt.Tun.Mtu < 1 {
		abort("mtu size too large or too small")
	}

	if bot.tox,e = New(bot.tox_opt); e != nil {
		abort("failed to build a new tox instance", e)
	}

	if e := bot.tox.Self_set_name(bot.opt.Name); e != nil {
		abort(e)
	}

	if e := bot.tox.Self_set_status_message(bot.opt.StMsg); e != nil {
		abort(e)
	}

	bot.tunconfig = yamux.DefaultConfig()
	bot.tunconfig.KeepAliveInterval,_ = time.ParseDuration(bot.opt.Tun.AliveInterval)
	bot.tunconfig.ConnectionWriteTimeout,_ = time.ParseDuration(bot.opt.Tun.ConnTimeout)
	bot.tunconfig.MaxStreamWindowSize = uint32(bot.opt.Tun.MaxStreamWindowSize)
	if e := yamux.VerifyConfig(bot.tunconfig); e != nil {
		abort("failed to config tun", e, bot.tunconfig)
	}

	for _,node := range bot.opt.Nodes {
		if node.Status_udp {
			if e := bot.tox.Bootstrap(node.Ipv4, node.Port, node.Public_key); e != nil {
				abort("failed to add node(udp mode)", e)
			}
		}

		if node.Status_tcp {
			for _,v := range node.Tcp_ports {
				if e := bot.tox.Add_tcp_relay(node.Ipv4, v, node.Public_key); e != nil {
					abort("failed to add nodes(relay mode)", e)
				}
			}
		}
	}
	bot.id = bot.tox.Self_address()
	bot.stime = time.Now()
	log.Println("Id:", bot.id)
	log.Println("Name:", bot.opt.Name)
	log.Println("StatusMessage:", bot.opt.StMsg)
	log.Println("Config:", bot.config)
	log.Println("ConfigMode:", bot.configMode)
	log.Println("Save:", bot.opt.Save)
	log.Println("SaveMode:", bot.opt.SaveMode)
	log.Println("Log:", bot.opt.Log)
	log.Println("WikiFetch:", bot.opt.WikiFetch)
	log.Println("Server:", bot.opt.Tun.Server)
	log.Println("Mtu:", bot.opt.Tun.Mtu)
	log.Println("KeepAliveInterval:", bot.opt.Tun.AliveInterval)
	log.Println("ConnTimeout:", bot.opt.Tun.ConnTimeout)
	log.Println("MaxStreamWindowSize:", bot.opt.Tun.MaxStreamWindowSize)
	log.Println("Qiniu url:", bot.opt.Qiniu.Url)

	bot.tox.Set_callback("callback_self_connection_status", self_connection_status)
	bot.tox.Set_callback("callback_friend_name", friend_name)
	bot.tox.Set_callback("callback_friend_status", friend_status)
	bot.tox.Set_callback("callback_friend_status_message", friend_status_message)
	bot.tox.Set_callback("callback_friend_connection_status", friend_connection_status)
	bot.tox.Set_callback("callback_friend_request", friend_request)
	bot.tox.Set_callback("callback_friend_message", friend_message)
	bot.tox.Set_callback("callback_friend_lossless_packet", friend_lossless_packet)

	sigext := make(chan os.Signal, 1)
	signal.Notify(sigext, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigext
		bot.tox.StopIterateLoop()
	}()

	_,e = bot.tox.Friend_add(bot.opt.Tun.Server, "tun client")
	if e != nil && e != ErrFriendAddAlreadySent {
		abort("cant add server as a friend:", e)
	}

	go bot.tox.IterateLoop(func() {
		if e := save(); e != nil {
			log.Println(e)
		}
		clean()
		os.Exit(0)
	})

	l,e := net.Listen("tcp", ":2528")
	if e != nil {
		abort(e)
	}
	defer l.Close()

	for {
		conn,e := l.Accept()
		if e != nil {
			log.Println(e)
			continue
		}

		go handle_conn(conn)
	}
}
