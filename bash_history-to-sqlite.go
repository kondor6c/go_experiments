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
)
import _ "github.com/mattn/go-sqlite3" //I don't understand this:  https://stackoverflow.com/questions/21220077/what-does-an-underscore-in-front-of-an-import-statement-mean-in-golang 

func get_opts() {
}

func main() {
	var db_file string
	var command string
	var exec_time string
	var bookmark string
	var install bool
	var full_scan bool
	
	flag.StringVar(&db_file,"dbfile",".bash_history.sqlite","sqlite database file location")
	flag.StringVar(&bookmark,"bookmark","!last","command id/line to bookmark")
	flag.BoolVar(&full_scan,"full",false,"scan full bash history instead of just the end")
	flag.BoolVar(&install,"install",false,"Install bashquil to PROMPT_COMMAND")
	flag.Parse()

	bash_history_File, _ := os.Open("/home/kondor6c/.bash_history")
	bash_history_scanner := bufio.NewScanner(bash_history_File)
	database, _ := sql.Open("sqlite3", db_file)

	create_statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS bash_history (id INTEGER PRIMARY KEY, exec_time INTEGER, host TEXT, command TEXT, bookmark TEXT, tag TEXT, frequency INTEGER)")
	create_statement.Exec()
	create_statement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS quick_history_table (id INTEGER PRIMARY KEY, exec_time INTEGER, host TEXT, commmand TEXT )")
	create_statement.Exec()
	create_statement, _ = database.Prepare("INSERT INTO bash_history (exec_time, host, command, bookmark, tag, frequency) VALUES (?, ?, ?, ?, ?, ?)")
	host, _ := os.Hostname()
	for bash_history_scanner.Scan() {
		if len(bash_history_scanner.Text()) == 11 {
			exec_time = bash_history_scanner.Text()[1:10]
		} else {
			command = bash_history_scanner.Text()
		}
		if len(command) > 2 {
			create_statement.Exec(exec_time, host, command,nil,nil,nil)
		}
	}
}
