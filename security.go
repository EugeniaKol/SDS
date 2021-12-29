package main

import (
	"fmt"
	"os"
	"time"
)

type Keys struct {
	public  *PublicKey
	private *PrivateKey
	name    string
}

type Entry struct {
	Denial   bool
	Username string
	Action   string
	Time     time.Time
}

type Info struct {
	Users      []*User
	keys       []*Keys
	Violations []Entry
}

var info Info = Info{
	Users: []*User{
		{
			Name:     "user",
			password: "qwerty",
		},
		{
			Name:     "admin",
			password: "010203",
		},
	},
}

func Login(fs *FileSystem) *FSHandler {
	fmt.Println("enter your name")
	name := GetInput(os.Stdin)
	for _, user := range info.Users {
		if user.Name == name {
			fmt.Println("enter your password")
			pass := GetInput(os.Stdin)
			for i := 0; i < 2; i++ {
				if user.password == pass {
					return InitHandler(user, &FSE)
				}
			}
			fmt.Println("a violation - incorrect password 3 times")
			newEntry := Entry{
				Denial:   true,
				Username: name,
				Action:   "password_violation",
				Time:     time.Now(),
			}
			fs.Info.Violations = append(info.Violations, newEntry)
		}
	}
	return nil
}

func (h *FSHandler) RegisterUser(user *User) bool {
	if !h.User.Privilege {
		newEntry := Entry{
			Denial:   true,
			Username: h.User.Name,
			Action:   "illegal_registration",
			Time:     time.Now(),
		}
		h.FS.Info.Violations = append(info.Violations, newEntry)
		return false
	}
	fmt.Println("user registered")
	h.FS.Info.Users = append(h.FS.Info.Users, user)
	return true
}

func (h *FSHandler) VerifyUser() bool {
	fmt.Println("time to enter secret phrase")
	phrase := GetInput(os.Stdin)
	for i := 0; i < 2; i++ {
		if phrase == h.User.phrase {
			fmt.Println("secret phrase is correct\n resuming session")
			return true
		}
	}
	newEntry := Entry{
		Denial:   true,
		Username: h.User.Name,
		Action:   "failed_secret_phrase",
		Time:     time.Now(),
	}
	h.FS.Info.Violations = append(info.Violations, newEntry)
	return false
}

func (h *FSHandler) ViewEntries() {
	if !h.User.Privilege {
		newEntry := Entry{
			Denial:   true,
			Username: h.User.Name,
			Action:   "illegal_entries_request",
			Time:     time.Now(),
		}
		h.FS.Info.Violations = append(info.Violations, newEntry)
		return
	}
	fmt.Println(h.FS.Info.Violations)
}
