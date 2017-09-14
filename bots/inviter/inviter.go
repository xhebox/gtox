package main

import (
	"os"
	"fmt"
	"strings"
	"bytes"
	"time"
	"github.com/xhebox/gtox"
)

var list []uint32
var passwd string

func friend_request(m *gtox.Tox, pubkey string, message string) {
	m.Friend_add_norequest(pubkey)
	var data = m.Savedata()
	var f, err = os.OpenFile("save.bin", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Printf("Failed to save: %s\n", err)
	}
	f.Seek(0, 0)
	f.Write(data)
	f.Close()

	fid,_ := m.Friend_by_public_key(pubkey)
	name,_ := m.Friend_name(fid)
	fmt.Printf("Added friend { %d : %s }, message: [ %s ]\n", fid, name, message)
}

func friend_connect(m *gtox.Tox, fid uint32, status gtox.Connection_t) {
	if status != gtox.CONNECTION_NONE {
		for _, gid := range list {
			name,_ := m.Friend_name(fid)
			title,_ := m.Conference_title(gid)

			fmt.Printf("Invite { %d : %s } to { %d : %s }\n", fid, name, gid, title);
			r, err := m.Conference_invite(fid, gid)
			if r && err != nil {
				fmt.Printf("Failed to invite { %d : %s }: %s\n", fid, name, err);
			}
		}
	}
}

func group_invite(m *gtox.Tox, fid uint32, t gtox.Conference_type, cookie []byte) {
	r, err := m.Conference_join(fid, cookie)
	if err != nil {
		name,_ := m.Friend_name(fid)
		fmt.Printf("Failed to accept invitation from { %d : %s }: %s\n", fid, name, err);
	}
	list = append(list, r)
}

func self_connection_status(m *gtox.Tox, ct gtox.Connection_t) {
	switch ct {
	case gtox.CONNECTION_NONE:
		fmt.Printf("Offline, reset groups list\n")
		for _,v := range list {
			m.Conference_del(v)
		}
	case gtox.CONNECTION_TCP:
		fmt.Printf("Online with TCP\n")
	case gtox.CONNECTION_UDP:
		fmt.Printf("Online with UDP\n")
	}
}

func friend_message(m *gtox.Tox, fid uint32, mtype gtox.Msg_t, message string) {
	if mtype == gtox.MSG_NORMAL {
		if strings.Compare(message, "groups") == 0 {
			var buffer bytes.Buffer
			buffer.WriteString("Groups: {\n")
			for _,v := range list {
				title,_ := m.Conference_title(v)
				buffer.WriteString(fmt.Sprintf("%d: %s\n", v, title));
			}
			buffer.WriteString("}")
			m.Friend_send_message(fid, gtox.MSG_NORMAL, buffer.String())
		}
		if strings.Compare(message, "help") == 0 {
			var buffer bytes.Buffer
			buffer.WriteString("Commands:\ngroups -- list all groups on the invitation list\nreset[passwd] -- reset the invitation list\n")
			m.Friend_send_message(fid, gtox.MSG_NORMAL, buffer.String())
		}
		if strings.Compare(message, fmt.Sprintf("reset%s", passwd)) == 0 {
			fmt.Printf("Received reset groups command, executing\n")
			for _,v := range list {
				m.Conference_del(v)
			}
		}
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
	var name = string("Inviter")
	tox.Self_set_name(name)

	var stmsg = string("Invite!")
	tox.Self_set_status_message(stmsg)

	tox.Bootstrap(string("tox.deadteam.org"), 33445, string("C7D284129E83877D63591F14B3F658D77FF9BA9BA7293AEB2BDFBFE1A803AF47"))

	var id = tox.Self_address()
	fmt.Printf("Bot id: %s\nplease input a passwd:\n", id)
	_, err := fmt.Scanf("%s", &passwd)
	if err != nil {
		fmt.Printf("Failed to set passwd: %s\n", err)
		os.Exit(1)
	}

	tox.Callback_friend_request(friend_request)
	tox.Callback_self_connection_status(self_connection_status)
	tox.Callback_conference_invite(group_invite)
	tox.Callback_friend_connection_status(friend_connect)
	tox.Callback_friend_message(friend_message)

	for {
		tox.Iterate()
		time.Sleep(time.Duration(tox.Iteration_interval()) * 1000)
	}

	opt.Del()
	tox.Kill()
}
