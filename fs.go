package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"
)

type Permission struct {
	Plain      int
	Privileged int
}

type User struct {
	Name      string
	password  string
	Privilege bool
	phrase    string
}

type FileUnit struct {
	Name        string
	Content     []byte
	Permissions Permission
}

type FileSystem struct {
	Info  *Info
	File  []*FileUnit
	Delta int
}

type FSHandler struct {
	FS   *FileSystem
	User *User
}

var FSE FileSystem = FileSystem{
	File: []*FileUnit{
		{
			Name:    "file1",
			Content: []byte{07, 07},
			Permissions: Permission{
				Plain:      1,
				Privileged: 7,
			},
		},
		{
			Name:    "file2",
			Content: []byte{03, 07},
			Permissions: Permission{
				Plain:      3,
				Privileged: 7,
			},
		},
	},
	Delta: 30}

func InitHandler(user *User, fs *FileSystem) *FSHandler {
	var handler FSHandler
	handler.User = user
	handler.FS = fs
	return &handler
}

func (h *FSHandler) Open(unit *FileUnit) (bool, []byte) {
	if h.User.Privilege {
		if unit.Permissions.Privileged >= 1 {
			return true, unit.Content
		}
		return false, nil
	}

	if unit.Permissions.Plain >= 1 {
		return true, unit.Content
	}
	return false, nil
}

func (h *FSHandler) Write(unit *FileUnit, content []byte) bool {
	if h.User.Privilege {
		if unit.Permissions.Privileged >= 2 {
			unit.Content = append(unit.Content, content...)
			return true
		}
		return false
	}

	if unit.Permissions.Plain >= 2 {
		unit.Content = append(unit.Content, content...)
		return true
	}
	return false
}

func (h *FSHandler) Execute(unit *FileUnit) bool {
	if h.User.Privilege {
		if unit.Permissions.Privileged >= 4 {
			return true
		}
		return false
	}

	if unit.Permissions.Plain >= 4 {
		return true
	}
	return false
}

func (h *FSHandler) FindFile(name string) *FileUnit {
	for _, f := range h.FS.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

type Response struct {
	Denial  bool
	Content []byte
}

func (h *FSHandler) HandleAction(op string) (Response, bool) {
	fmt.Println("enter a command")
	switch op {
	case "open":
		name := GetInput(os.Stdin)
		file := h.FindFile(name)
		success, content := h.Open(file)
		if !success {
			return Response{
				Denial:  true,
				Content: nil,
			}, false
		}
		return Response{
			Denial:  false,
			Content: content,
		}, false
	case "write":
		name := GetInput(os.Stdin)
		content := GetInput(os.Stdin)
		file := h.FindFile(name)
		success := h.Write(file, []byte(content))
		if !success {
			return Response{
				Denial:  true,
				Content: nil,
			}, false
		}
		return Response{
			Denial:  false,
			Content: nil,
		}, false
	case "execute":
		name := GetInput(os.Stdin)
		file := h.FindFile(name)
		success := h.Execute(file)
		if !success {
			return Response{
				Denial:  true,
				Content: nil,
			}, false
		}
		return Response{
			Denial:  false,
			Content: []byte{01},
		}, false
	case "entries":
		h.ViewEntries()
		break
	case "register":
		name := GetInput(os.Stdin)
		password := GetInput(os.Stdin)
		phrase := GetInput(os.Stdin)
		newUser := User{
			Name:      name,
			password:  password,
			Privilege: false,
			phrase:    phrase,
		}
		res := h.RegisterUser(&newUser)

		return Response{Denial: res, Content: nil}, false
	case "verify":
		res := h.VerifyUser()
		return Response{}, res
	case "exit":
		break

	default:
		break
	}
	return Response{Denial: false, Content: nil}, false
}

func GetInput(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanWords)
	scanner.Scan()
	return scanner.Text()
}

func (h *FSHandler) Listen() {
	actions := 0
	for {
		var action string
		if actions%h.FS.Delta == 0 {
			action = "verify"
		} else {
			action = GetInput(os.Stdin)
			_, signal := h.HandleAction(action)
			if signal {
				break
			}
		}
		response, signal := h.HandleAction(action)
		if response.Denial {
			newEntry := Entry{
				Denial:   true,
				Username: h.User.Name,
				Action:   "denied_access",
				Time:     time.Time{},
			}
			fmt.Println("access denied. this will be reported")
			h.FS.Info.Violations = append(h.FS.Info.Violations, newEntry)
			continue
		}
		if signal {
			break
		}
		fmt.Println(response.Content)
		actions++
	}
}

func Session() {
	fmt.Println("please log in for system access")
	handler := Login(&FSE)

	if handler != nil {
		fmt.Println("login successful")
		handler.Listen()
	}
}
