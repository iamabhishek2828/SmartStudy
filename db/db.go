package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func InitDB() {
	dsn := "root:Abhi@2828@tcp(127.0.0.1:3306)/smartstudy?parseTime=true"
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Error opening DB:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("Error pinging DB:", err)
	}
	fmt.Println("Connected to MySQL database!")
}

func CreateUser(username, email, password, role string) (int64, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("bcrypt error: %v", err)
	}

	query := `
    INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, NOW(), NOW())`

	res, err := DB.Exec(query, username, email, hashedPassword, role)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func ValidateUser(username, password string) (bool, error) {
	var storedHash string
	err := DB.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&storedHash)
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		return false, nil // password mismatch
	}

	return true, nil
}

func CreateQuiz(title string) (int64, error) {
	query := "INSERT INTO quizzes (title, created_at) VALUES (?, NOW())"
	res, err := DB.Exec(query, title)
	if err != nil {
		return 0, fmt.Errorf("error creating quiz: %v", err)
	}
	return res.LastInsertId()
}
func AddQuestionToQuiz(quizID int64, question string, options []string, correctOption, explanation string) error {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("error marshaling options: %v", err)
	}

	query := `
		INSERT INTO quiz_questions (quiz_id, question, options, correct_option, explanation, created_at)
		VALUES (?, ?, ?, ?, ?, NOW())`
	_, err = DB.Exec(query, quizID, question, string(optionsJSON), correctOption, explanation)
	return err
}
func CreateAssignment(tutorID int, title, filePath, description string) (int64, error) {
	query := "INSERT INTO assignments (tutor_id, title, file_path, description, created_at) VALUES (?, ?, ?, ?, NOW())"
	res, err := DB.Exec(query, tutorID, title, filePath, description)
	if err != nil {
		return 0, fmt.Errorf("error creating assignment: %v", err)
	}
	return res.LastInsertId()
}
func CreateMaterial(tutorID int, title, filePath, description, content string) (int64, error) {
	query := "INSERT INTO materials (tutor_id, title, file_path, description, content, created_at) VALUES (?, ?, ?, ?, ?, NOW())"
	res, err := DB.Exec(query, tutorID, title, filePath, description, content)
	if err != nil {
		return 0, fmt.Errorf("error creating study material: %v", err)
	}
	return res.LastInsertId()
}
func RecordStudentQuiz(studentID int, score float64, totalQ, correctAns int) error {
	query := `
		INSERT INTO quizzes (student_id, score, total_question, correct_answers)
		VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, studentID, score, totalQ, correctAns)
	if err != nil {
		return fmt.Errorf("error recording student quiz: %v", err)
	}
	return nil
}
func RecordStudentQuizAttempt(studentID, quizID int, score float64, totalQ, correctAns int) error {
	query := `
      INSERT INTO student_quiz_attempts (student_id, quiz_id, score, total_questions, correct_answers)
      VALUES (?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, studentID, quizID, score, totalQ, correctAns)
	return err
}
