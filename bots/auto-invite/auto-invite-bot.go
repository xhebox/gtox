package main

import (
	"os"
	"fmt"
	"time"
	"github.com/xhebox/gtox"
)

var list []uint32

func friend_request(m *gtox.Tox, pubkey string, message string) {
	m.Friend_add_norequest(pubkey)
	var data = m.Savedata()
	var f, err = os.OpenFile("save.bin", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	f.Seek(0, 0)
	f.Write(data)
	f.Close()
	fmt.Print("added friend, message: ", message, "\n")
}

func friend_connect(m *gtox.Tox, fid uint32, status gtox.Connection_t) {
	if status != gtox.CONNECTION_NONE {
		for _, gid := range list {
			fmt.Print("try to invite ", fid, " to ", gid, "\n")
			r, err := m.Conference_invite(fid, gid)
			if r && err != nil {
				fmt.Print(err)
				os.Exit(1)
			}
		}
	}
}

func group_invite(m *gtox.Tox, fid uint32, t gtox.Conference_type, cookie []byte) {
	r, err := m.Conference_join(fid, cookie)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	list = append(list, r)

	fmt.Print("group id list: ", list, "\n")
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
	var name = string("Auto invite Bot")
	tox.Self_set_name(name)

	var stmsg = string("Invite!")
	tox.Self_set_status_message(stmsg)

	tox.Bootstrap(string("tox.zodiaclabs.org"), 33445, string("A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074"))

	var id = tox.Self_address()
	fmt.Printf("id: %s\n", id)

	tox.Callback_friend_request(friend_request)
	tox.Callback_self_connection_status(self_connection_status)
	tox.Callback_conference_invite(group_invite)
	tox.Callback_friend_connection_status(friend_connect)

	for {
		tox.Iterate()
		time.Sleep(time.Duration(tox.Iteration_interval()) * 1000)
	}

	opt.Del()
	tox.Kill()
}
