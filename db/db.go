package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func InitDB() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN environment variable not set")
	}
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Error opening DB:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("Error pinging DB:", err)
	}
	log.Println("Connected to MySQL database!")
}
func CreateUser(username, email, password, role string) (int64, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("bcrypt error: %w", err)
	}
	res, err := DB.Exec(`
        INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, NOW(), NOW())`,
		username, email, string(hashedBytes), role,
	)
	if err != nil {
		return 0, fmt.Errorf("insert error: %w", err)
	}
	return res.LastInsertId()
}
func ValidateUser(username, incomingDigest string) (bool, error) {
	var storedHash []byte
	err := DB.QueryRow(
		"SELECT password_hash FROM users WHERE username = ?", username,
	).Scan(&storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if err := bcrypt.CompareHashAndPassword(storedHash, []byte(incomingDigest)); err != nil {
		return false, nil
	}
	return true, nil
}
func CreateQuiz(title string) (int64, error) {
	res, err := DB.Exec("INSERT INTO quizzes (title, created_at) VALUES (?, NOW())", title)
	if err != nil {
		return 0, fmt.Errorf("error creating quiz: %v", err)
	}
	return res.LastInsertId()
}
func AddQuestionToQuiz(quizID int64, question string, options []string, correctOption, explanation string) error {
	optsJSON, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("error marshaling options: %v", err)
	}

	_, err = DB.Exec(
		`INSERT INTO quiz_questions (quiz_id, question, options, correct_option, explanation, created_at)
		 VALUES (?, ?, ?, ?, ?, NOW())`,
		quizID, question, string(optsJSON), correctOption, explanation,
	)
	return err
}
func CreateAssignment(tutorID int, title, filePath, description string, dueDate time.Time) (int64, error) {
	res, err := DB.Exec(
		`INSERT INTO assignments (tutor_id, title, file_path, description, due_date, created_at)
		 VALUES (?, ?, ?, ?, ?, NOW())`,
		tutorID, title, filePath, description, dueDate,
	)
	if err != nil {
		return 0, fmt.Errorf("error creating assignment: %v", err)
	}
	return res.LastInsertId()
}

func CreateMaterial(tutorID int, title, filePath, description, content string) (int64, error) {
	res, err := DB.Exec(
		`INSERT INTO materials (tutor_id, title, file_path, description, content, created_at)
		 VALUES (?, ?, ?, ?, ?, NOW())`,
		tutorID, title, filePath, description, content,
	)
	if err != nil {
		return 0, fmt.Errorf("error creating material: %v", err)
	}
	return res.LastInsertId()
}
func RecordStudentQuiz(studentID int, score float64, totalQ, correctAns int) error {
	_, err := DB.Exec(
		`INSERT INTO quizzes (student_id, score, total_question, correct_answers)
		 VALUES (?, ?, ?, ?)`,
		studentID, score, totalQ, correctAns,
	)
	return err
}
func RecordStudentQuizAttempt(studentID, quizID int, score float64, totalQuestions, correctAnswers int) error {
	_, err := DB.Exec(
		`INSERT INTO student_quiz_attempts (student_id, quiz_id, score, total_questions, correct_answers, submitted_at)
		 VALUES (?, ?, ?, ?, ?, NOW())`,
		studentID, quizID, score, totalQuestions, correctAnswers,
	)
	return err
}
