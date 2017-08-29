package main

import (
	"os"
	"fmt"
	"time"
	"github.com/xhebox/gtox"
)

func friend_request(m *gtox.Tox, pubkey string, message string) {
	m.Friend_add_norequest(pubkey)
	var data = m.Savedata()
	var f, _ = os.OpenFile("save.bin", os.O_RDWR|os.O_CREATE, 0755)
	f.Seek(0, 0)
	f.Write(data)
	f.Close()
}

func friend_message(m *gtox.Tox, fid uint32, mt gtox.Msg_t, message string) {
	m.Friend_send_message(fid, mt, message)
}

func self_connection_status(m *gtox.Tox, ct gtox.Connection_t) {
	switch ct {
	case gtox.CONNECTION_NONE:
		fmt.Printf("offline\n")
	case gtox.CONNECTION_TCP:
		fmt.Printf("online with TCP\n")
	case gtox.CONNECTION_UDP:
		fmt.Printf("online with UDP\n")
	}
}

func main() {
	var tox gtox.Tox
	var opt gtox.Tox_options
	opt.New()

	var f, e = os.Open("save.bin")
	if e == nil {
		var i, _ = f.Stat()
		if i.Size() != 0 {
			var data = make([]byte, i.Size())
			f.Read(data)
			f.Close()
			opt.Savedata_length = uint32(i.Size())
			opt.Savedata_type = gtox.SAVEDATA_TYPE_TOX_SAVE
			opt.Savedata_data = append(opt.Savedata_data, data...)
		}
	}

	tox.New(opt)
	var name = string("Echo Bot")
	tox.Self_set_name(name)

	var stmsg = string("Echo it!")
	tox.Self_set_status_message(stmsg)

	tox.Bootstrap(string("tox.zodiaclabs.org"), 33445, string("A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074"))

	var id = tox.Self_address()
	fmt.Printf("id: %s\n", id)

	tox.Callback_friend_request(friend_request)
	tox.Callback_friend_message(friend_message)
	tox.Callback_self_connection_status(self_connection_status)

	for {
		tox.Iterate()
		time.Sleep(time.Duration(tox.Iteration_interval()) * 1000)
	}

	opt.Del()
	tox.Kill()
}
