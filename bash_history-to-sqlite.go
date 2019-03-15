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
	"os"
	"strings"
	"strconv"
	"fmt"
)
import _ "github.com/mattn/go-sqlite3" //I don't understand this:  https://stackoverflow.com/questions/21220077/what-does-an-underscore-in-front-of-an-import-statement-mean-in-golang 

func create_db(sqliteFile *string) ( *sql.DB ) { 
	db, _ := sql.Open("sqlite3", *sqliteFile) //we tell the standard lib sql we want to use sqlite3 driver
	create_statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS bash_history (id INTEGER PRIMARY KEY, exec_time INTEGER, host TEXT, command TEXT, exit_status INTEGER, bookmark TEXT, tag TEXT, frequency INTEGER)")
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
	exec_time int
	host string
	command string
	exit_status int
	bookmark string
	tag string
	frequency int
}

func main() {
	var (
		dbfile = flag.String("dbfile",".bash_history.sqlite","sqlite database file location")
		//bookmark = flag.String("bookmark","!last","command id/line to bookmark")
		//full_scan = flag.Bool("full",false,"scan full bash history instead of just the end")
		//install = flag.Bool("install",false,"Install bashquil to PROMPT_COMMAND")
	)

	flag.Parse()
	db := create_db(dbfile)
	sql_history, _ := db.Prepare("INSERT INTO bash_history (exec_time, host, command, exit_status, bookmark, tag, frequency) VALUES (?, ?, ?, ?, ?, ?)")
	var env_setting []string = os.Environ()
	var tty string
	for index, _ := range env_setting {
		if env_setting[index] == "GPG_TTY" {
			tty = env_setting[index]
			break
		}
	}
	var user string = os.Getenv("USER")
	hostname, _ := os.Hostname()
	location := []string{ hostname, tty }
	hostname = strings.Join(location,":")
	copy(hostname[1:],user)
	bash_history_File, _ := os.Open("/home/kondor6c/.bash_history")
	bash_history := bufio.NewReader(bash_history_File)
	staged_row := &HistRow{host: hostname }

	for {
		line, err := bash_history.ReadString('\n') 
		Catcher(err)
		staged_row.get(line)
		exec_line, err := bash_history.ReadString('\n') 
		Catcher(err)
		staged_row.get(exec_line)
		sql_history.Exec(staged_row.exec_time, staged_row.host, staged_row.command,nil,nil,nil)
	}
}


/* Also called methods 6.2.1
https://stackoverflow.com/questions/23542989/pointers-vs-values-in-parameters-and-return-values
https://stackoverflow.com/questions/32208363/returning-value-vs-pointer-in-go-constructor
*/
func (hist *HistRow) get(line string) { //nil pointer panics avoided by using a pointer
	if len(line) == 11 { //If the line is a timestamp
		hist.exec_time, _ = strconv.Atoi(line[1:10])
	} else if len(line) > 2 {
		hist.command = line
	} else {
		fmt.Println("error")
	}
}

func compare_entry(line string, timestamp string, row_number int) {

}
