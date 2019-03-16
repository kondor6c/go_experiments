// https://unix.stackexchange.com/questions/18212/bash-history-ignoredups-and-erasedups-setting-conflict-with-common-history
// ^ PROMPT_COMMAND="history -n; history -w; history -c; history -r; $PROMPT_COMMAND"
// -n Read the history lines not already read from the history file into the current history list.
//    These are lines appended to the history file since the beginning of the current bash session.
// -w Write the current history list to the history file, overwriting the history file's contents.
// -c clear the history list by deleting all the entries
// -r Read the contents of the history file and append them to the current history list
// If set, the value is interpreted as a command to execute before the printing of each ($PS1)
// -a Append the ``new'' history lines to the history file.  These are history lines entered since the
//    beginning of the current bash session, but not already appended to the history file.
// GATHER TTY, would be useful to get context on when something was executed and what was next
package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"os"
	"runtime/pprof"
	"strconv"
)

func create_db(sqliteFile *string) *sql.DB {
	db, err := sql.Open("sqlite3", *sqliteFile) //we tell the standard lib sql we want to use sqlite3 driver
	Catcher(err)                                // I cringe now that I see I was discarding the error, this caused me issues
	create_statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS bash_history (id INTEGER PRIMARY KEY, exec_time INTEGER, user_host_location TEXT, command TEXT, exit_status INTEGER, bookmark TEXT, tag TEXT, frequency INTEGER)")
	create_statement.Exec()
	create_statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS quick_history_table (id INTEGER PRIMARY KEY, exec_time INTEGER, host TEXT, commmand TEXT )")
	create_statement.Exec()
	return db //return the actual values, the function will point to this value
}

func Catcher(err error) {
	if err != nil {
		panic(err)
	}
}

type HistRow struct {
	exec_time   int
	host        string
	command     string
	exit_status int
	bookmark    string
	tag         string
	frequency   int
}

func main() {
	go pprof.StartCPUProfile(os.Stdout)
	defer pprof.StopCPUProfile()
	var (
		dbfile = flag.String("dbfile", ".bash_history.sqlite", "sqlite database file location")
		//bookmark = flag.String("bookmark","#!!last","command id/line to bookmark")
		//full_scan = flag.Bool("full",false,"scan full bash history instead of just the end")
		//install = flag.Bool("install",false,"Install bashquil to PROMPT_COMMAND")
	)

	flag.Parse()
	db := create_db(dbfile)
	sql_history, err := db.Prepare("INSERT INTO bash_history (exec_time, user_host_location, command, exit_status, bookmark, tag, frequency) VALUES (?, ?, ?, ?, ?, ?, ?)")
	Catcher(err)
	hostname, _ := os.Hostname()
	tty, _ := os.Readlink("/proc/self/fd/0")
	// https://github.com/go101/go101/wiki/How-to-efficiently-clone-a-slice%3F
	// how is a slice of a slice laid out in memory?
	// How efficient are bytes and byte array's compared to strings? I imagine byte arrays are more efficient, but how
	// three dots ... variadaric
	// Totally could have done all this with string operations and builder, but I wanted to use the builtin append and attempt copy()

	user := append([]byte(os.Getenv("USER")), []byte("@")[0])
	host := append([]byte(hostname), []byte(":")[0])
	location := append(user, host...)
	location = append(location, []byte(tty)...)

	bash_history_File, fileErr := os.Open("/home/kondor6c/.bash_history")
	Catcher(fileErr)
	bash_history := bufio.NewReader(bash_history_File)
	staged_row := &HistRow{host: string(location)}

	for {
		line, err := bash_history.ReadString('\n')
		if err == io.EOF {
			db.Close()
			os.Exit(3)
		} else if err != nil {
			panic(err)
		}
		staged_row.get(line)
		exec_line, err := bash_history.ReadString('\n')
		Catcher(err)
		staged_row.get(exec_line)
		sql_history.Exec(staged_row.exec_time, staged_row.host, staged_row.command, nil, nil, nil)
	}
}

/* Also called methods 6.2.1
https://stackoverflow.com/questions/23542989/pointers-vs-values-in-parameters-and-return-values
https://stackoverflow.com/questions/32208363/returning-value-vs-pointer-in-go-constructor
*/
// I might need to re-write this!!
// https://blog.golang.org/share-memory-by-communicating
func (hist *HistRow) get(line string) { //nil pointer panics avoided by using a pointer
	if len(line) == 11 { //If the line is a timestamp
		hist.exec_time, _ = strconv.Atoi(line[1:10])
	} else if len(line) > 2 { // I totally need a better check! this fails on my favorite command "w"
		hist.command = line
	} else {
		fmt.Println("error on history line")
		fmt.Println(line)
	}
}

func compare_entry(line string, timestamp string, row_number int) {

}
